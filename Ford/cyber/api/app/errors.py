"""Respostas de erro padronizadas no formato RFC 9457 (application/problem+json).

Nenhuma resposta de erro expõe stack trace, SQL, caminho de arquivo ou versão de
biblioteca. O detalhe técnico fica só no log, ligado à resposta pelo request_id.
"""
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .logging_setup import logger

PROBLEM_JSON = "application/problem+json"


class ApiError(Exception):
    def __init__(self, status: int, code: str, detail: str, headers: dict | None = None):
        self.status = status
        self.code = code
        self.detail = detail
        self.headers = headers or {}


def problem(request: Request, status: int, code: str, detail: str,
            headers: dict | None = None, errors: list | None = None) -> JSONResponse:
    body = {
        "type": f"https://api.vinshare.example/errors/{code}",
        "title": code,
        "status": status,
        "detail": detail,
        "instance": request.url.path,
        "request_id": getattr(request.state, "request_id", None),
    }
    if errors:
        body["errors"] = errors
    hdrs = dict(headers or {})
    if status == 401:
        hdrs.setdefault("WWW-Authenticate", 'Bearer realm="vinshare"')
    return JSONResponse(body, status_code=status, headers=hdrs, media_type=PROBLEM_JSON)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError):
        return problem(request, exc.status, exc.code, exc.detail, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        # Devolve só campo + motivo; o valor enviado NÃO é ecoado (pode conter PII ou payload malicioso)
        errors = [{"field": ".".join(str(p) for p in e["loc"][1:]), "reason": e["msg"]}
                  for e in exc.errors()]
        return problem(request, 422, "validation_error", "Dados de entrada inválidos", errors=errors)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        codes = {404: "not_found", 405: "method_not_allowed"}
        return problem(request, exc.status_code, codes.get(exc.status_code, "http_error"),
                       str(exc.detail) if exc.status_code < 500 else "Erro interno")

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        logger.error("unhandled_exception", exc_info=exc,
                     extra={"event": "app.error", "path": request.url.path,
                            "request_id": getattr(request.state, "request_id", None)})
        return problem(request, 500, "internal_error", "Erro interno. Informe o request_id ao suporte.")
