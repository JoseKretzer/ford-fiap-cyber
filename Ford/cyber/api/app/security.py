"""Autenticação (JWT) e autorização (RBAC por perfil + escopo por concessionária).

Perfis do VIN Share (equivalentes aos níveis operacional/gestor/admin do enunciado):
  - consultor : consultor de serviço da concessionária. Vê e trabalha os leads da SUA concessionária.
  - gestor    : gestor da concessionária. Tudo do consultor + indicadores (Service Share) e predições.
  - admin     : administrador Ford. Acesso a todas as concessionárias, usuários e trilha de auditoria.
"""
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Callable

import bcrypt
import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .errors import ApiError
from .logging_setup import audit

ALGORITHM = "HS256"          # algoritmo fixo: tokens com "alg": "none" ou RS/HS trocados são rejeitados
REQUIRED_CLAIMS = ["sub", "role", "dealer_id", "iat", "nbf", "exp", "iss", "aud", "jti"]
BCRYPT_ROUNDS = 12
# Hash válido usado quando o usuário não existe, para que o tempo de resposta
# seja igual ao de uma senha errada (evita enumeração de usuários por timing).
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(BCRYPT_ROUNDS))


class Role(str, Enum):
    CONSULTOR = "consultor"
    GESTOR = "gestor"
    ADMIN = "admin"


# Permissões por perfil (menor privilégio). Checadas no servidor, nunca no app.
PERMISSIONS: dict[Role, set[str]] = {
    Role.CONSULTOR: {"leads:read", "leads:update"},
    Role.GESTOR: {"leads:read", "leads:update", "service_share:read", "predictions:create"},
    Role.ADMIN: {"leads:read", "leads:update", "service_share:read", "predictions:create",
                 "audit:read", "users:manage", "dealers:all"},
}


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: Role
    dealer_id: str
    jti: str
    exp: int

    def can(self, permission: str) -> bool:
        return permission in PERMISSIONS[self.role]

    def can_access_dealer(self, dealer_id: str) -> bool:
        return self.can("dealers:all") or self.dealer_id == dealer_id


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(BCRYPT_ROUNDS)).decode()


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        if password_hash is None:
            bcrypt.checkpw(password.encode(), _DUMMY_HASH)
            return False
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:  # ex.: senha > 72 bytes (limite do bcrypt)
        return False


class TokenService:
    def __init__(self, secret: str, issuer: str, audience: str, ttl_seconds: int):
        self._secret = secret
        self._issuer = issuer
        self._audience = audience
        self.ttl = ttl_seconds
        self._revoked: dict[str, int] = {}   # jti -> exp (em produção: Redis com TTL)

    def issue(self, user_id: str, role: Role, dealer_id: str) -> str:
        now = int(time.time())
        claims = {
            "sub": user_id,
            "role": role.value,
            "dealer_id": dealer_id,
            "iat": now,
            "nbf": now,
            "exp": now + self.ttl,
            "iss": self._issuer,
            "aud": self._audience,
            "jti": uuid.uuid4().hex,
        }
        # Somente identificadores e perfil vão no token: nada de nome, CPF, e-mail
        # (o payload do JWT é apenas Base64, não é cifrado).
        return jwt.encode(claims, self._secret, algorithm=ALGORITHM)

    def validate(self, token: str) -> Principal:
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=[ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": REQUIRED_CLAIMS},
                leeway=5,
            )
            role = Role(claims["role"])
        except jwt.ExpiredSignatureError as exc:
            raise ApiError(401, "token_expired", "Token expirado") from exc
        except (jwt.InvalidTokenError, ValueError) as exc:
            raise ApiError(401, "invalid_token", "Token inválido") from exc

        if claims["jti"] in self._revoked:
            raise ApiError(401, "token_revoked", "Token revogado")

        return Principal(claims["sub"], role, claims["dealer_id"], claims["jti"], claims["exp"])

    def revoke(self, principal: Principal) -> None:
        now = int(time.time())
        self._revoked = {j: e for j, e in self._revoked.items() if e > now}  # limpa expirados
        self._revoked[principal.jti] = principal.exp


_bearer = HTTPBearer(auto_error=False)


def current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise ApiError(401, "missing_token", "Autenticação necessária")
    try:
        principal = request.app.state.tokens.validate(credentials.credentials)
    except ApiError as err:
        audit("auth.token_rejected", request, reason=err.code)
        request.app.state.metrics.token_rejected.labels(reason=err.code).inc()
        raise
    request.state.principal = principal
    return principal


def require(permission: str) -> Callable[..., Principal]:
    def dependency(request: Request, principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.can(permission):
            audit("authz.denied", request, user_id=principal.user_id,
                  role=principal.role.value, permission=permission)
            request.app.state.metrics.authz_denied.labels(permission=permission).inc()
            raise ApiError(403, "forbidden", "Perfil sem permissão para este recurso")
        return principal
    return dependency


def ensure_dealer_access(request: Request, principal: Principal, dealer_id: str) -> None:
    """Proteção contra BOLA/IDOR (OWASP API1): o ID na URL não basta,
    o recurso precisa pertencer à concessionária do usuário."""
    if not principal.can_access_dealer(dealer_id):
        audit("authz.denied", request, user_id=principal.user_id, role=principal.role.value,
              permission="dealer_scope", target_dealer=dealer_id)
        request.app.state.metrics.authz_denied.labels(permission="dealer_scope").inc()
        raise ApiError(403, "forbidden", "Acesso negado a dados de outra concessionária")
