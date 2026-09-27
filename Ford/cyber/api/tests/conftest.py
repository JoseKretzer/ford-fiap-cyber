import base64
import os
import secrets

import pytest
from fastapi.testclient import TestClient

# Segredos gerados a cada execução: nenhum segredo fica gravado no repositório.
os.environ.update({
    "APP_ENV": "test",
    "JWT_SECRET": secrets.token_urlsafe(48),
    "DATA_KEY_B64": base64.b64encode(secrets.token_bytes(32)).decode(),
    "INDEX_KEY_B64": base64.b64encode(secrets.token_bytes(32)).decode(),
    "DEMO_PASSWORD": secrets.token_urlsafe(18),
    "CORS_ORIGINS": "https://app.vinshare.example",
})

from app.main import create_app  # noqa: E402

DEMO_PASSWORD = os.environ["DEMO_PASSWORD"]


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def login(client):
    def _login(username: str, password: str = DEMO_PASSWORD) -> dict:
        resp = client.post("/api/v1/auth/login", json={"username": username, "password": password})
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}
    return _login
