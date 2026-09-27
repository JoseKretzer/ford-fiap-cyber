"""Validação de entrada por allow-list (OWASP API3/API8, ASVS V5).

- extra="forbid": campos não previstos são rejeitados (bloqueia mass assignment,
  ex.: enviar "role": "admin" ou "dealer_id" no PATCH).
- Tamanhos, faixas numéricas, enums e regex explícitos para cada campo.
"""
import re
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")  # inclui \r e \n; só TAB é aceito


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginRequest(Strict):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=64)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    role: str


class LeadStatus(str, Enum):
    NOVO = "novo"
    CONTATADO = "contatado"
    AGENDADO = "agendado"
    CONVERTIDO = "convertido"
    PERDIDO = "perdido"


class LeadUpdate(Strict):
    status: LeadStatus
    note: str | None = Field(default=None, max_length=500)

    @field_validator("note")
    @classmethod
    def no_control_chars(cls, v: str | None) -> str | None:
        # Evita log injection (quebras de linha forjadas) e caracteres de controle
        if v is not None and _CONTROL_CHARS.search(v):
            raise ValueError("caracteres de controle não são permitidos")
        return v


class LeadOut(BaseModel):
    id: str
    dealer_id: str
    customer_name: str
    cpf: str                 # sempre mascarado (minimização - LGPD art. 6, III)
    phone: str               # necessário para o consultor contatar o cliente
    vehicle_model: str
    vehicle_year: int
    months_since_last_visit: int
    churn_risk: float
    status: LeadStatus


class ServiceShareOut(BaseModel):
    dealer_id: str
    period: str
    vehicles_in_territory: int
    vehicles_serviced: int
    service_share: float


FordModel = Literal["Ranger", "Territory", "Bronco Sport", "Maverick", "Transit", "Mustang Mach-E"]


class ChurnPredictionRequest(Strict):
    model: FordModel
    vehicle_age_years: int = Field(ge=0, le=30)
    km_since_last_service: int = Field(ge=0, le=200_000)
    months_since_last_visit: int = Field(ge=0, le=120)
    services_last_24m: int = Field(ge=0, le=50)
    warranty_active: bool
    connected_vehicle: bool


class ChurnPredictionOut(BaseModel):
    churn_probability: float
    risk: Literal["baixo", "medio", "alto"]
    model_version: str
