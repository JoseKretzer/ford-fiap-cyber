"""Logs estruturados em JSON (uma linha por evento), prontos para Loki / Azure Monitor.

Regras:
  - Todo evento tem timestamp UTC, nível, nome do evento e request_id (correlação).
  - Eventos de segurança (login, falha, negação, alteração crítica) vão para o logger
    'vinshare.audit', que em produção é retido por 1 ano e é somente-anexo.
  - Campos sensíveis (senha, token, CPF, telefone, e-mail) são mascarados pelo
    RedactingFilter, mesmo que algum desenvolvedor os passe por engano.
"""
import json
import logging
import sys
from datetime import datetime, timezone

from fastapi import Request

SENSITIVE_KEYS = {"password", "senha", "token", "access_token", "authorization",
                  "cpf", "phone", "telefone", "email", "secret", "vin"}
_STD_ATTRS = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        for key in list(vars(record)):
            if key.lower() in SENSITIVE_KEYS:
                setattr(record, key, "[REDACTED]")
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STD_ATTRS and not key.startswith("_"):
                entry[key] = value
        if record.exc_info:
            entry["exc_type"] = record.exc_info[0].__name__
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


def _build(name: str) -> logging.Logger:
    log = logging.getLogger(name)
    if not log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        handler.addFilter(RedactingFilter())
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        log.propagate = True
    return log


logger = _build("vinshare.api")
audit_logger = _build("vinshare.audit")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def audit(event: str, request: Request, **fields) -> None:
    audit_logger.info(event, extra={
        "event": event,
        "request_id": getattr(request.state, "request_id", None),
        "client_ip": client_ip(request),
        "method": request.method,
        "path": request.url.path,
        **fields,
    })
