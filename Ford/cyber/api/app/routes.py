"""Endpoints REST (nível 2 de maturidade) da API VIN Share.

Públicos : GET /health, POST /auth/login
Protegidos: todo o resto, com permissão por perfil + escopo por concessionária.
"""
from fastapi import APIRouter, Depends, Query, Request, Response

from .crypto import mask_cpf
from .errors import ApiError
from .logging_setup import audit, client_ip
from .schemas import (ChurnPredictionOut, ChurnPredictionRequest, LeadOut, LeadStatus,
                      LeadUpdate, LoginRequest, ServiceShareOut, TokenResponse)
from .security import Principal, current_principal, ensure_dealer_access, require, verify_password
from .store import SERVICE_SHARE, Lead

router = APIRouter(prefix="/api/v1")


def _lead_out(request: Request, lead: Lead) -> LeadOut:
    cipher = request.app.state.store.cipher
    return LeadOut(
        id=lead.id, dealer_id=lead.dealer_id, customer_name=lead.customer_name,
        cpf=mask_cpf(cipher.decrypt(lead.cpf_enc, "customer.cpf")),
        phone=cipher.decrypt(lead.phone_enc, "customer.phone"),
        vehicle_model=lead.vehicle_model, vehicle_year=lead.vehicle_year,
        months_since_last_visit=lead.months_since_last_visit,
        churn_risk=lead.churn_risk, status=LeadStatus(lead.status),
    )


def _get_lead_scoped(request: Request, principal: Principal, lead_id: str) -> Lead:
    lead = request.app.state.store.leads.get(lead_id)
    if lead is None:
        raise ApiError(404, "not_found", "Lead não encontrado")
    if not principal.can_access_dealer(lead.dealer_id):
        # Responde 404 (e não 403) para não revelar que o lead existe em outra concessionária
        audit("authz.denied", request, user_id=principal.user_id, role=principal.role.value,
              permission="dealer_scope", target_dealer=lead.dealer_id)
        request.app.state.metrics.authz_denied.labels(permission="dealer_scope").inc()
        raise ApiError(404, "not_found", "Lead não encontrado")
    return lead


@router.get("/health", tags=["público"])
def health() -> dict:
    return {"status": "ok"}


@router.post("/auth/login", response_model=TokenResponse, tags=["público"])
def login(body: LoginRequest, request: Request) -> TokenResponse:
    app = request.app.state
    ip = client_ip(request)
    for limiter, key, scope in ((app.login_limiter, f"{ip}|{body.username}", "login_user"),
                                (app.login_ip_limiter, ip, "login_ip")):
        allowed, retry_after = limiter.check(key)
        if not allowed:
            audit("auth.login.blocked", request, username=body.username, scope=scope)
            app.metrics.rate_limited.labels(scope=scope).inc()
            raise ApiError(429, "too_many_requests", "Muitas tentativas de login. Tente novamente mais tarde.",
                           {"Retry-After": str(retry_after)})

    user = app.store.users.get(body.username)
    if not verify_password(body.password, user.password_hash if user else None) or not user.active:
        audit("auth.login.failure", request, username=body.username)
        app.metrics.login.labels(result="failure").inc()
        # Mensagem genérica: não informa se o usuário existe
        raise ApiError(401, "invalid_credentials", "Usuário ou senha inválidos")

    app.login_limiter.reset(f"{ip}|{body.username}")
    token = app.tokens.issue(user.id, user.role, user.dealer_id)
    audit("auth.login.success", request, user_id=user.id, role=user.role.value, dealer_id=user.dealer_id)
    app.metrics.login.labels(result="success").inc()
    return TokenResponse(access_token=token, expires_in=app.tokens.ttl, role=user.role.value)


@router.post("/auth/logout", status_code=204, tags=["autenticação"])
def logout(request: Request, principal: Principal = Depends(current_principal)) -> Response:
    request.app.state.tokens.revoke(principal)
    audit("auth.logout", request, user_id=principal.user_id)
    return Response(status_code=204)


@router.get("/me", tags=["autenticação"])
def me(principal: Principal = Depends(current_principal)) -> dict:
    return {"user_id": principal.user_id, "role": principal.role.value, "dealer_id": principal.dealer_id}


@router.get("/dealers/{dealer_id}/leads", response_model=list[LeadOut], tags=["leads"])
def list_leads(dealer_id: str, request: Request,
               status: LeadStatus | None = Query(default=None),
               principal: Principal = Depends(require("leads:read"))) -> list[LeadOut]:
    ensure_dealer_access(request, principal, dealer_id)
    leads = [lead for lead in request.app.state.store.leads.values()
             if lead.dealer_id == dealer_id and (status is None or lead.status == status.value)]
    return [_lead_out(request, lead) for lead in sorted(leads, key=lambda l: -l.churn_risk)]


@router.get("/leads/{lead_id}", response_model=LeadOut, tags=["leads"])
def get_lead(lead_id: str, request: Request,
             principal: Principal = Depends(require("leads:read"))) -> LeadOut:
    return _lead_out(request, _get_lead_scoped(request, principal, lead_id))


@router.patch("/leads/{lead_id}", response_model=LeadOut, tags=["leads"])
def update_lead(lead_id: str, body: LeadUpdate, request: Request,
                principal: Principal = Depends(require("leads:update"))) -> LeadOut:
    lead = _get_lead_scoped(request, principal, lead_id)
    old = lead.status
    lead.status = body.status.value
    if body.note:
        lead.notes.append(body.note)
    audit("lead.status_changed", request, user_id=principal.user_id, lead_id=lead.id,
          dealer_id=lead.dealer_id, old_status=old, new_status=lead.status)
    return _lead_out(request, lead)


@router.get("/dealers/{dealer_id}/service-share", response_model=ServiceShareOut, tags=["indicadores"])
def service_share(dealer_id: str, request: Request,
                  principal: Principal = Depends(require("service_share:read"))) -> ServiceShareOut:
    ensure_dealer_access(request, principal, dealer_id)
    data = SERVICE_SHARE.get(dealer_id)
    if data is None:
        raise ApiError(404, "not_found", "Concessionária não encontrada")
    share = round(data["vehicles_serviced"] / data["vehicles_in_territory"], 4)
    return ServiceShareOut(dealer_id=dealer_id, service_share=share, **data)


@router.post("/predictions/churn", response_model=ChurnPredictionOut, tags=["ml"])
def predict_churn(body: ChurnPredictionRequest, request: Request,
                  principal: Principal = Depends(require("predictions:create"))) -> ChurnPredictionOut:
    model = request.app.state.model
    p = model.predict(body)
    risk = model.risk_band(p)
    request.app.state.metrics.predictions.labels(risk=risk).inc()
    request.app.state.metrics.prediction_score.observe(p)
    return ChurnPredictionOut(churn_probability=p, risk=risk, model_version=model.version)


@router.get("/admin/audit-events", tags=["admin"])
def audit_events(request: Request, limit: int = Query(default=50, ge=1, le=500),
                 principal: Principal = Depends(require("audit:read"))) -> list[dict]:
    return list(request.app.state.audit_buffer.records)[-limit:]
