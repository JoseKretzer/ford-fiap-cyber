"""Serviço de inferência do modelo de churn (risco de o veículo sair da rede Ford).

Segurança do artefato de ML:
  - O modelo é distribuído como JSON de coeficientes, NUNCA como pickle
    (pickle executa código arbitrário ao ser carregado).
  - O SHA-256 do artefato é verificado antes do carregamento. O hash esperado é
    gerado no pipeline de treino e injetado via variável de ambiente, então um
    artefato trocado no storage não é carregado.

Os coeficientes aqui são de referência; o modelo treinado na disciplina de IA/ML
é exportado para o mesmo formato.
"""
import hashlib
import json
import math
import os
from pathlib import Path

from .schemas import ChurnPredictionRequest

DEFAULT_PATH = Path(__file__).parent / "churn_model.json"


class ModelIntegrityError(RuntimeError):
    pass


class ChurnModel:
    def __init__(self, path: Path = DEFAULT_PATH, expected_sha256: str | None = None):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if expected_sha256 and digest != expected_sha256.lower():
            raise ModelIntegrityError(f"Hash do modelo não confere ({digest[:12]}...)")
        spec = json.loads(raw)
        self.version: str = spec["version"]
        self.intercept: float = spec["intercept"]
        self.coef: dict[str, float] = spec["coefficients"]
        self.model_coef: dict[str, float] = spec["model_offsets"]
        self.sha256 = digest

    @classmethod
    def from_env(cls) -> "ChurnModel":
        path = Path(os.environ.get("MODEL_PATH", DEFAULT_PATH))
        return cls(path, os.environ.get("MODEL_SHA256"))

    def predict(self, x: ChurnPredictionRequest) -> float:
        z = (self.intercept
             + self.coef["vehicle_age_years"] * x.vehicle_age_years
             + self.coef["km_since_last_service_10k"] * (x.km_since_last_service / 10_000)
             + self.coef["months_since_last_visit"] * x.months_since_last_visit
             + self.coef["services_last_24m"] * x.services_last_24m
             + self.coef["warranty_active"] * int(x.warranty_active)
             + self.coef["connected_vehicle"] * int(x.connected_vehicle)
             + self.model_coef.get(x.model, 0.0))
        return round(1 / (1 + math.exp(-z)), 4)

    @staticmethod
    def risk_band(p: float) -> str:
        return "alto" if p >= 0.7 else "medio" if p >= 0.4 else "baixo"
