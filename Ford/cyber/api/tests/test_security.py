"""Testes de segurança da API VIN Share (executados em todo PR pelo pipeline DevSecOps)."""
import base64
import json
import logging
import os
import time

import jwt
import pytest

from app.crypto import DecryptionError, FieldCipher, mask_cpf
from app.model import ChurnModel, ModelIntegrityError

from .conftest import DEMO_PASSWORD

SECRET = os.environ["JWT_SECRET"]


def _forge(claims_override: dict, secret: str = SECRET, alg: str = "HS256") -> str:
    now = int(time.time())
    claims = {"sub": "u-100", "role": "consultor", "dealer_id": "SP01", "iat": now, "nbf": now,
              "exp": now + 600, "iss": "vinshare-api", "aud": "vinshare-app", "jti": "x" * 32}
    claims.update(claims_override)
    return jwt.encode(claims, secret, algorithm=alg)


# ---------------------------------------------------------------- Autenticação / JWT
class TestAuthentication:
    def test_health_is_public(self, client):
        assert client.get("/api/v1/health").status_code == 200

    def test_login_success_returns_short_lived_jwt(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "gestor.sp01", "password": DEMO_PASSWORD})
        assert resp.status_code == 200
        body = resp.json()
        claims = jwt.decode(body["access_token"], SECRET, algorithms=["HS256"], audience="vinshare-app")
        assert claims["exp"] - claims["iat"] == 900
        assert {"sub", "role", "dealer_id", "jti"} <= claims.keys()
        assert "password" not in claims and "cpf" not in claims

    @pytest.mark.parametrize("username", ["gestor.sp01", "usuario.inexistente"])
    def test_login_failure_is_generic(self, client, username):
        resp = client.post("/api/v1/auth/login", json={"username": username, "password": "senha-errada-123"})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Usuário ou senha inválidos"
        assert resp.headers["content-type"] == "application/problem+json"

    def test_protected_endpoint_without_token(self, client):
        resp = client.get("/api/v1/me")
        assert resp.status_code == 401
        assert resp.headers["WWW-Authenticate"].startswith("Bearer")

    @pytest.mark.parametrize("token,code", [
        (_forge({"exp": int(time.time()) - 60}), "token_expired"),
        (_forge({}, secret="outra-chave-qualquer-com-32-caracteres!!"), "invalid_token"),
        (_forge({"aud": "outro-sistema"}), "invalid_token"),
        (_forge({"iss": "emissor-falso"}), "invalid_token"),
        (_forge({"role": "superuser"}), "invalid_token"),
        (_forge({}, alg="none", secret=None), "invalid_token"),
    ], ids=["expirado", "assinatura_errada", "audience_errada", "issuer_errado", "perfil_invalido", "alg_none"])
    def test_rejects_bad_tokens(self, client, token, code):
        resp = client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
        assert resp.json()["title"] == code

    def test_rejects_token_missing_required_claim(self, client):
        now = int(time.time())
        token = jwt.encode({"sub": "u-100", "exp": now + 600, "iss": "vinshare-api", "aud": "vinshare-app"},
                           SECRET, algorithm="HS256")
        assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    def test_tampered_payload_is_rejected(self, client, login):
        headers = login("consultor.sp01")
        header, payload, sig = headers["Authorization"][7:].split(".")
        data = json.loads(base64.urlsafe_b64decode(payload + "=="))
        data["role"] = "admin"
        forged = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
        resp = client.get("/api/v1/admin/audit-events",
                          headers={"Authorization": f"Bearer {header}.{forged}.{sig}"})
        assert resp.status_code == 401

    def test_logout_revokes_token(self, client, login):
        headers = login("consultor.sp01")
        assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
        resp = client.get("/api/v1/me", headers=headers)
        assert resp.status_code == 401
        assert resp.json()["title"] == "token_revoked"


# ---------------------------------------------------------------- Autorização (RBAC + BOLA)
class TestAuthorization:
    def test_consultor_cannot_read_audit(self, client, login):
        assert client.get("/api/v1/admin/audit-events", headers=login("consultor.sp01")).status_code == 403

    def test_consultor_cannot_read_service_share(self, client, login):
        resp = client.get("/api/v1/dealers/SP01/service-share", headers=login("consultor.sp01"))
        assert resp.status_code == 403

    def test_gestor_reads_own_dealer_service_share(self, client, login):
        resp = client.get("/api/v1/dealers/SP01/service-share", headers=login("gestor.sp01"))
        assert resp.status_code == 200
        assert resp.json()["service_share"] == pytest.approx(0.45, abs=0.01)

    def test_gestor_cannot_read_other_dealer(self, client, login):
        resp = client.get("/api/v1/dealers/RJ02/service-share", headers=login("gestor.sp01"))
        assert resp.status_code == 403

    def test_bola_lead_of_other_dealer_returns_404(self, client, login):
        resp = client.get("/api/v1/leads/L-2001", headers=login("consultor.sp01"))
        assert resp.status_code == 404

    def test_leads_are_scoped_to_dealer(self, client, login):
        resp = client.get("/api/v1/dealers/SP01/leads", headers=login("consultor.sp01"))
        assert resp.status_code == 200
        assert {lead["dealer_id"] for lead in resp.json()} == {"SP01"}

    def test_admin_accesses_any_dealer(self, client, login):
        headers = login("admin.ford")
        assert client.get("/api/v1/dealers/RJ02/leads", headers=headers).status_code == 200
        assert client.get("/api/v1/admin/audit-events", headers=headers).status_code == 200

    def test_mass_assignment_is_blocked(self, client, login):
        resp = client.patch("/api/v1/leads/L-1001", headers=login("consultor.sp01"),
                            json={"status": "agendado", "dealer_id": "RJ02"})
        assert resp.status_code == 422


# ---------------------------------------------------------------- Validação / hardening
class TestHardening:
    def test_valid_lead_update(self, client, login):
        resp = client.patch("/api/v1/leads/L-1001", headers=login("consultor.sp01"),
                            json={"status": "agendado", "note": "Revisão marcada"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "agendado"

    @pytest.mark.parametrize("payload", [
        {"status": "hackeado"},
        {"status": "agendado", "note": "x" * 501},
        {"status": "agendado", "note": "linha1\r\nFAKE LOG ENTRY"},
    ], ids=["enum_invalido", "texto_longo", "log_injection"])
    def test_invalid_input_rejected(self, client, login, payload):
        resp = client.patch("/api/v1/leads/L-1001", headers=login("consultor.sp01"), json=payload)
        assert resp.status_code == 422
        body = resp.json()
        assert body["title"] == "validation_error"
        assert "FAKE LOG" not in json.dumps(body)  # valor enviado não é ecoado

    def test_ml_input_bounds(self, client, login):
        payload = {"model": "Ranger", "vehicle_age_years": 99, "km_since_last_service": 5000,
                   "months_since_last_visit": 3, "services_last_24m": 2,
                   "warranty_active": True, "connected_vehicle": True}
        resp = client.post("/api/v1/predictions/churn", headers=login("gestor.sp01"), json=payload)
        assert resp.status_code == 422

    def test_ml_prediction_ok(self, client, login):
        payload = {"model": "Transit", "vehicle_age_years": 6, "km_since_last_service": 25000,
                   "months_since_last_visit": 18, "services_last_24m": 0,
                   "warranty_active": False, "connected_vehicle": False}
        resp = client.post("/api/v1/predictions/churn", headers=login("gestor.sp01"), json=payload)
        assert resp.status_code == 200
        assert resp.json()["risk"] == "alto"

    def test_login_rate_limit(self, client):
        for _ in range(5):
            client.post("/api/v1/auth/login", json={"username": "gestor.sp01", "password": "tentativa-errada-1"})
        resp = client.post("/api/v1/auth/login", json={"username": "gestor.sp01", "password": DEMO_PASSWORD})
        assert resp.status_code == 429
        assert int(resp.headers["Retry-After"]) > 0

    def test_payload_too_large(self, client, login):
        resp = client.patch("/api/v1/leads/L-1001", headers={**login("consultor.sp01"),
                            "Content-Type": "application/json"}, content=b"{" + b" " * 70_000 + b"}")
        assert resp.status_code == 413

    def test_security_headers(self, client):
        headers = client.get("/api/v1/health").headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert "max-age" in headers["Strict-Transport-Security"]
        assert headers["Cache-Control"] == "no-store"
        assert "X-Request-ID" in headers

    def test_cors_blocks_unknown_origin(self, client):
        resp = client.options("/api/v1/health", headers={"Origin": "https://site-malicioso.example",
                                                        "Access-Control-Request-Method": "GET"})
        assert "access-control-allow-origin" not in resp.headers

    @pytest.mark.parametrize("version,status", [("0.9.3", 426), ("1.0.0", 200), ("1.2.10", 200), ("1.0;DROP", 426)],
                             ids=["versao_antiga", "versao_minima", "versao_nova", "versao_invalida"])
    def test_minimum_app_version(self, client, version, status):
        resp = client.get("/api/v1/health", headers={"X-App-Version": version})
        assert resp.status_code == status

    def test_prod_requires_model_hash(self, monkeypatch):
        from app.config import ConfigError, load_settings
        monkeypatch.setenv("APP_ENV", "prod")
        monkeypatch.delenv("MODEL_SHA256", raising=False)
        with pytest.raises(ConfigError):
            load_settings()

    def test_unhandled_error_does_not_leak(self, app, client):
        @app.get("/api/v1/boom")
        def boom():
            raise RuntimeError("segredo interno: postgres://user:pass@db")
        resp = client.get("/api/v1/boom")
        assert resp.status_code == 500
        assert "postgres" not in resp.text and "Traceback" not in resp.text


# ---------------------------------------------------------------- Criptografia e dados pessoais
class TestDataProtection:
    def test_pii_encrypted_at_rest(self, app):
        lead = app.state.store.leads["L-1001"]
        assert "11122233344" not in lead.cpf_enc
        assert lead.cpf_enc.startswith("k1:")

    def test_cpf_masked_in_api(self, client, login):
        lead = client.get("/api/v1/leads/L-1001", headers=login("consultor.sp01")).json()
        assert lead["cpf"] == "***.***.***-44"

    def test_ciphertext_tampering_detected(self):
        cipher = FieldCipher({"k1": os.urandom(32)}, "k1", os.urandom(32))
        token = cipher.encrypt("11122233344", "customer.cpf")
        raw = bytearray(base64.b64decode(token[3:]))
        raw[-1] ^= 0x01
        with pytest.raises(DecryptionError):
            cipher.decrypt("k1:" + base64.b64encode(bytes(raw)).decode(), "customer.cpf")

    def test_ciphertext_cannot_be_moved_between_fields(self):
        cipher = FieldCipher({"k1": os.urandom(32)}, "k1", os.urandom(32))
        token = cipher.encrypt("11122233344", "customer.cpf")
        with pytest.raises(DecryptionError):
            cipher.decrypt(token, "customer.phone")

    def test_key_rotation_reads_old_data(self):
        old, new, idx = os.urandom(32), os.urandom(32), os.urandom(32)
        token = FieldCipher({"k1": old}, "k1", idx).encrypt("dado", "ctx")
        rotated = FieldCipher({"k1": old, "k2": new}, "k2", idx)
        assert rotated.decrypt(token, "ctx") == "dado"
        assert rotated.encrypt("dado", "ctx").startswith("k2:")

    def test_blind_index_search(self, app):
        assert app.state.store.find_lead_by_cpf("111.222.333-44").id == "L-1001"

    def test_mask_cpf(self):
        assert mask_cpf("123.456.789-01") == "***.***.***-01"

    def test_model_integrity_check(self, tmp_path):
        artifact = tmp_path / "model.json"
        artifact.write_bytes(open(os.path.join(os.path.dirname(__file__), "..", "app", "churn_model.json"), "rb").read())
        with pytest.raises(ModelIntegrityError):
            ChurnModel(artifact, expected_sha256="0" * 64)


# ---------------------------------------------------------------- Logs de auditoria
class TestAuditLogging:
    def test_login_events_logged_without_secrets(self, client, caplog):
        with caplog.at_level(logging.INFO, logger="vinshare.audit"):
            client.post("/api/v1/auth/login", json={"username": "gestor.sp01", "password": "senha-errada-123"})
            client.post("/api/v1/auth/login", json={"username": "gestor.sp01", "password": DEMO_PASSWORD})
        events = [r.event for r in caplog.records if hasattr(r, "event")]
        assert "auth.login.failure" in events and "auth.login.success" in events
        everything_logged = " ".join(str(vars(r)) for r in caplog.records)
        assert DEMO_PASSWORD not in everything_logged and "senha-errada-123" not in everything_logged

    def test_authz_denied_is_audited(self, client, login, caplog):
        headers = login("consultor.sp01")
        with caplog.at_level(logging.INFO, logger="vinshare.audit"):
            client.get("/api/v1/admin/audit-events", headers=headers)
        assert any(getattr(r, "event", "") == "authz.denied" for r in caplog.records)

    def test_critical_change_is_audited(self, client, login):
        client.patch("/api/v1/leads/L-1002", headers=login("gestor.sp01"), json={"status": "contatado"})
        events = client.get("/api/v1/admin/audit-events", headers=login("admin.ford")).json()
        change = next(e for e in events if e["event"] == "lead.status_changed")
        assert change["old_status"] == "novo" and change["new_status"] == "contatado"
