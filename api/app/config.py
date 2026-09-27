"""Configuração da API VIN Share.

Todos os segredos vêm de variáveis de ambiente (injetadas pelo GitHub Secrets /
Azure Key Vault em produção). A aplicação falha no startup se algum segredo
estiver ausente ou fraco, em vez de subir com valor padrão inseguro.
"""
import base64
import os
from dataclasses import dataclass, field


class ConfigError(RuntimeError):
    pass


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"Variável de ambiente obrigatória ausente: {name}")
    return value


@dataclass(frozen=True)
class Settings:
    env: str
    jwt_secret: str
    jwt_issuer: str
    jwt_audience: str
    jwt_ttl_seconds: int
    data_key: bytes            # chave AES-256 para criptografia de PII em repouso
    data_key_id: str           # identifica a chave (permite rotação)
    index_key: bytes           # chave HMAC para índice cego (busca por CPF sem decifrar)
    cors_origins: list[str] = field(default_factory=list)
    min_app_version: tuple[int, int, int] = (1, 0, 0)   # versões com falha de segurança conhecida são recusadas (426)
    login_rate_limit: int = 5          # tentativas por janela
    login_rate_window: int = 60        # segundos
    api_rate_limit: int = 100
    api_rate_window: int = 60
    max_body_bytes: int = 64 * 1024

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"


def load_settings() -> Settings:
    jwt_secret = _require("JWT_SECRET")
    if len(jwt_secret) < 32:
        raise ConfigError("JWT_SECRET deve ter pelo menos 32 caracteres (256 bits)")

    data_key = base64.b64decode(_require("DATA_KEY_B64"))
    if len(data_key) != 32:
        raise ConfigError("DATA_KEY_B64 deve conter exatamente 32 bytes (AES-256)")

    index_key = base64.b64decode(_require("INDEX_KEY_B64"))
    if len(index_key) < 32:
        raise ConfigError("INDEX_KEY_B64 deve conter pelo menos 32 bytes")

    ttl = int(os.environ.get("JWT_TTL_SECONDS", "900"))
    if not 60 <= ttl <= 3600:
        raise ConfigError("JWT_TTL_SECONDS deve ficar entre 60 e 3600 segundos")

    origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
    if "*" in origins:
        raise ConfigError("CORS_ORIGINS não pode conter '*'")

    env = os.environ.get("APP_ENV", "dev")
    if env == "prod" and not os.environ.get("MODEL_SHA256"):
        # Em produção o modelo só carrega com o hash gerado pelo pipeline (ver ChurnModel)
        raise ConfigError("MODEL_SHA256 é obrigatório em produção")

    # Sem `assert` aqui: com `python -O` os asserts somem e a validação deixaria de existir (Bandit B101)
    parts = os.environ.get("MIN_APP_VERSION", "1.0.0").split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ConfigError("MIN_APP_VERSION deve ter o formato X.Y.Z")
    min_app = tuple(int(p) for p in parts)

    return Settings(
        env=env,
        min_app_version=min_app,
        jwt_secret=jwt_secret,
        jwt_issuer=os.environ.get("JWT_ISSUER", "vinshare-api"),
        jwt_audience=os.environ.get("JWT_AUDIENCE", "vinshare-app"),
        jwt_ttl_seconds=ttl,
        data_key=data_key,
        data_key_id=os.environ.get("DATA_KEY_ID", "k1"),
        index_key=index_key,
        cors_origins=origins,
        login_rate_limit=int(os.environ.get("LOGIN_RATE_LIMIT", "5")),
        login_rate_window=int(os.environ.get("LOGIN_RATE_WINDOW", "60")),
        api_rate_limit=int(os.environ.get("API_RATE_LIMIT", "100")),
        api_rate_window=int(os.environ.get("API_RATE_WINDOW", "60")),
    )
