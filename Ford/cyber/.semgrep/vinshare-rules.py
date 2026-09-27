# Casos de teste das regras Semgrep (semgrep scan --test --config .semgrep/ .semgrep/)
import pickle

import jwt
from fastapi import APIRouter, Depends

router = APIRouter()


def jwt_cases(token, key):
    # ruleid: jwt-decode-without-verification
    jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": False})
    # ruleid: jwt-decode-without-verification
    jwt.decode(token, key, algorithms=["HS256", "none"])
    # ruleid: jwt-decode-without-algorithms
    jwt.decode(token, key)
    # ok: jwt-decode-without-algorithms
    jwt.decode(token, key, algorithms=["HS256"], audience="vinshare-app")


def model_cases(path):
    # ruleid: pickle-load-model
    return pickle.load(open(path, "rb"))


def log_cases(logger, pwd, cpf):
    # ruleid: logging-sensitive-field
    logger.info("login", extra={"user": "x", "password": pwd})
    # ruleid: logging-sensitive-field
    logger.info("cliente", extra={"cpf": cpf})
    # ok: logging-sensitive-field
    logger.info("login", extra={"user_id": "u-1"})


# ruleid: route-without-auth-dependency
@router.get("/leads/{lead_id}")
def unprotected(lead_id: str):
    return {}


# ok: route-without-auth-dependency
@router.get("/leads/{lead_id}/ok")
def protected(lead_id: str, principal: dict = Depends(lambda: {})):
    return {}


# ok: route-without-auth-dependency
@router.get("/health")
def health():
    return {}


def mqtt_cases(client):
    # ruleid: mqtt-without-tls
    client.connect("broker", 1883, 60)
    # ok: mqtt-without-tls
    client.connect("broker", 8883, 60)
