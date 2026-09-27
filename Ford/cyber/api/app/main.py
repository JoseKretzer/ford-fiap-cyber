"""Ponto de entrada da API VIN Share (FastAPI).

Camadas de proteção aplicadas a TODA requisição, nesta ordem:
  1. Request ID (correlação de logs)       5. Autenticação JWT (dependência da rota)
  2. Limite de tamanho do corpo (413)      6. Autorização por perfil + concessionária
  3. Rate limit global por cliente (429)   7. Validação de entrada (Pydantic, 422)
  4. Versão mínima do app mobile (426)
Na saída: cabeçalhos de segurança, métricas e log de acesso estruturado.
"""
import logging
import re
import time
import uuid
from collections import deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from .config import Settings, load_settings
from .crypto import FieldCipher
from .errors import problem, register_error_handlers
from .logging_setup import audit_logger, client_ip, logger
from .metrics import Metrics
from .model import ChurnModel
from .ratelimit import SlidingWindowLimiter
from .routes import router
from .security import TokenService
from .store import Store, seed_demo

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}
_REQUEST_ID = re.compile(r"^[a-zA-Z0-9-]{8,64}$")
_APP_VERSION = re.compile(r"^(\d{1,2})\.(\d{1,3})\.(\d{1,3})$")


def _parse_version(value: str | None) -> tuple[int, int, int] | None:
    match = _APP_VERSION.match(value or "")
    return tuple(int(g) for g in match.groups()) if match else None
_DOCS_PATHS = ("/docs", "/openapi.json", "/redoc")


class AuditBuffer(logging.Handler):
    """Mantém os últimos eventos de auditoria para o endpoint de admin."""
    def __init__(self, size: int = 500):
        super().__init__()
        self.records: deque[dict] = deque(maxlen=size)

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append({k: v for k, v in vars(record).items()
                             if k in {"event", "request_id", "user_id", "role", "username",
                                      "client_ip", "path", "permission", "lead_id",
                                      "old_status", "new_status", "reason", "created"}})


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(
        title="Ford VIN Share API",
        version="1.0.0",
        # Swagger só fora de produção (evita expor o inventário da API - OWASP API9)
        docs_url=None if settings.is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_prod else "/openapi.json",
    )

    cipher = FieldCipher({settings.data_key_id: settings.data_key}, settings.data_key_id, settings.index_key)
    app.state.settings = settings
    app.state.store = Store(cipher)
    app.state.tokens = TokenService(settings.jwt_secret, settings.jwt_issuer,
                                    settings.jwt_audience, settings.jwt_ttl_seconds)
    app.state.metrics = Metrics()
    app.state.model = ChurnModel.from_env()
    app.state.login_limiter = SlidingWindowLimiter(settings.login_rate_limit, settings.login_rate_window)
    app.state.login_ip_limiter = SlidingWindowLimiter(settings.login_rate_limit * 4, settings.login_rate_window)
    app.state.api_limiter = SlidingWindowLimiter(settings.api_rate_limit, settings.api_rate_window)
    app.state.audit_buffer = AuditBuffer()
    for handler in [h for h in audit_logger.handlers if isinstance(h, AuditBuffer)]:
        audit_logger.removeHandler(handler)
    audit_logger.addHandler(app.state.audit_buffer)
    seed_demo(app.state.store)

    register_error_handlers(app)
    app.include_router(router)

    if settings.is_prod:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["api.vinshare.example"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-App-Version"],
        allow_credentials=False,
    )

    @app.middleware("http")
    async def security_pipeline(request: Request, call_next):
        start = time.perf_counter()
        incoming = request.headers.get("X-Request-ID", "")
        request.state.request_id = incoming if _REQUEST_ID.match(incoming) else uuid.uuid4().hex

        length = request.headers.get("content-length")
        allowed, retry_after = app.state.api_limiter.check(client_ip(request))
        app_version = request.headers.get("X-App-Version")
        parsed_version = _parse_version(app_version)
        if app_version is not None:
            outdated = parsed_version is None or parsed_version < settings.min_app_version
            app.state.metrics.client_requests.labels(
                app_version if parsed_version else "outra", "bloqueada" if outdated else "aceita").inc()

        if length and (not length.isdigit() or int(length) > settings.max_body_bytes):
            response = problem(request, 413, "payload_too_large", "Corpo da requisição excede o limite")
        elif not allowed:
            app.state.metrics.rate_limited.labels(scope="api").inc()
            response = problem(request, 429, "too_many_requests", "Limite de requisições excedido",
                               {"Retry-After": str(retry_after)})
        elif app_version is not None and outdated:
            # App com falha de segurança conhecida: força atualização (OWASP Mobile M8)
            response = problem(request, 426, "upgrade_required",
                               "Versão do aplicativo não suportada. Atualize o app para continuar.")
        else:
            response = await call_next(request)

        # Rota "template" (/leads/{lead_id}) evita explosão de cardinalidade nas métricas
        route = getattr(request.scope.get("route"), "path", "unmatched")
        elapsed = time.perf_counter() - start
        app.state.metrics.requests.labels(request.method, route, str(response.status_code)).inc()
        app.state.metrics.latency.labels(route).observe(elapsed)

        for header, value in SECURITY_HEADERS.items():
            if header == "Content-Security-Policy" and request.url.path in _DOCS_PATHS:
                continue  # a página do Swagger (somente dev) precisa carregar JS/CSS
            response.headers.setdefault(header, value)
        response.headers["X-Request-ID"] = request.state.request_id

        principal = getattr(request.state, "principal", None)
        logger.info("http_request", extra={
            "event": "http.access",
            "request_id": request.state.request_id,
            "client_ip": client_ip(request),
            "method": request.method,
            "route": route,
            "status": response.status_code,
            "duration_ms": round(elapsed * 1000, 2),
            "user_id": principal.user_id if principal else None,
        })
        return response

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        # Exposto só na rede interna: o Ingress não roteia /metrics e a
        # NetworkPolicy só libera o namespace do Prometheus (ver infra/k8s).
        return Response(generate_latest(app.state.metrics.registry), media_type=CONTENT_TYPE_LATEST)

    return app


def get_app() -> FastAPI:  # usado pelo uvicorn: uvicorn app.main:get_app --factory
    return create_app()
