"""Simula 2 horas de operação do VIN Share (24 intervalos de 5 min) com ataques
injetados, executando a API e o validador de ingestão IoT reais em processo. Gera:

  - observability/exemplos_logs.jsonl : logs estruturados reais (API + ingestão IoT)
  - observability/serie_metricas.json : série temporal das métricas Prometheus por intervalo

Cenário:
  intervalos 0-23 : consultores e gestores usando o app (v1.2.0) e 6 veículos enviando telemetria
  intervalos 8-10 : força bruta no login do gestor.sp01 a partir de 203.0.113.50  (PB-01)
  intervalos 14-16: consultor.rj02 tentando ler leads/indicadores da SP01 (BOLA)   (PB-02)
  intervalo  19   : tokens forjados (alg=none / assinatura errada)               (PB-03)
  intervalos 21-22: replay de telemetria capturada + odômetro adulterado        (PB-04)
  intervalos 4-7  : aparelho com app desatualizado (v0.9.3) tentando acessar     (mobile)

Uso (a partir de cyber/):  .venv\\Scripts\\python observability\\simular_trafego.py
"""
import base64
import json
import logging
import os
import random
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(ROOT / "iot"))

os.environ.update({
    "APP_ENV": "dev",
    "JWT_SECRET": secrets.token_urlsafe(48),
    "DATA_KEY_B64": base64.b64encode(secrets.token_bytes(32)).decode(),
    "INDEX_KEY_B64": base64.b64encode(secrets.token_bytes(32)).decode(),
    "DEMO_PASSWORD": secrets.token_urlsafe(18),
    # 2 h de tráfego rodam em segundos: o limite global por IP (100/min) é elevado só aqui
    # para não bloquear usuários legítimos. O limite de login continua no padrão (5/min).
    "API_RATE_LIMIT": "100000",
})

from fastapi.testclient import TestClient  # noqa: E402

from app.logging_setup import JsonFormatter, RedactingFilter, audit_logger, logger  # noqa: E402
from app.main import create_app  # noqa: E402
from ingestion import TelemetryValidator, log as iot_logger  # noqa: E402

OUT_LOGS = ROOT / "observability" / "exemplos_logs.jsonl"
OUT_SERIES = ROOT / "observability" / "serie_metricas.json"
PASSWORD = os.environ["DEMO_PASSWORD"]
random.seed(42)

class _PerServiceFormatter(logging.Formatter):
    """Um único arquivo para API e IoT, cada um no seu formato JSON de produção."""
    def __init__(self):
        super().__init__()
        self.api, self.iot = JsonFormatter(), iot_logger.handlers[0].formatter

    def format(self, record):
        return (self.iot if record.name == "vinshare.iot" else self.api).format(record)


file_handler = logging.FileHandler(OUT_LOGS, mode="w", encoding="utf-8")
file_handler.setFormatter(_PerServiceFormatter())
file_handler.addFilter(RedactingFilter())
for log in (logger, audit_logger, iot_logger):
    log.handlers = [file_handler]
    log.propagate = False

app = create_app()
iot = TelemetryValidator()
APP_HEADERS = {"X-App-Version": "1.2.0"}
USERS = {"consultor.sp01": "10.1.4.21", "gestor.sp01": "10.1.4.35",
         "consultor.rj02": "10.2.7.12", "admin.ford": "10.9.0.5"}
clients = {u: TestClient(app, client=(ip, 50000), headers=APP_HEADERS) for u, ip in USERS.items()}
attacker = TestClient(app, client=("203.0.113.50", 41234))
old_app = TestClient(app, client=("10.1.4.77", 50000), headers={"X-App-Version": "0.9.3"})
VEHICLES = [f"veh-{i:016x}" for i in range(0xa1, 0xa7)]
odometer = {v: random.randint(20_000, 90_000) for v in VEHICLES}
T0 = 1_790_000_000  # relógio simulado da telemetria (segundos)


def login(user: str) -> dict:
    r = clients[user].post("/api/v1/auth/login", json={"username": user, "password": PASSWORD})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def snapshot() -> dict[str, float]:
    values: dict[str, float] = {}
    for registry in (app.state.metrics.registry, iot.registry):
        for metric in registry.collect():
            for s in metric.samples:
                if s.name.endswith("_created") or s.name.endswith("_timestamp_seconds"):
                    continue
                key = s.name + json.dumps(s.labels, sort_keys=True)
                values[key] = s.value
    return values


captured: list[tuple[str, bytes]] = []   # mensagens "capturadas" pelo atacante para replay


def telemetry(tick: int) -> None:
    now = T0 + tick * 300
    for v in VEHICLES:
        for k in range(random.randint(8, 12)):  # ~1 mensagem a cada 30 s por veículo
            odometer[v] += random.randint(0, 3)
            payload = json.dumps({"msg_id": secrets.token_hex(16), "ts": now + k * 25,
                                  "odometer_km": odometer[v], "dtc_codes": random.choice([[], [], ["P0420"]]),
                                  "oil_life_pct": random.randint(10, 90)}).encode()
            topic = f"vehicles/{v}/telemetry"
            iot.validate(topic, payload, now=now + k * 25)
            if tick == 20 and v == VEHICLES[0]:
                captured.append((topic, payload))
    if tick in (21, 22):  # atacante reenvia mensagens capturadas e tenta "voltar" o odômetro
        for topic, payload in captured:
            iot.validate(topic, payload, now=now)
        for _ in range(5):
            fake = json.dumps({"msg_id": secrets.token_hex(16), "ts": now, "odometer_km": 1000,
                               "dtc_codes": [], "oil_life_pct": 90}).encode()
            iot.validate(f"vehicles/{VEHICLES[0]}/telemetry", fake, now=now)


def normal_traffic(tokens: dict) -> None:
    for _ in range(random.randint(6, 10)):
        clients["consultor.sp01"].get("/api/v1/dealers/SP01/leads", headers=tokens["consultor.sp01"])
    for _ in range(random.randint(3, 6)):
        clients["consultor.rj02"].get("/api/v1/dealers/RJ02/leads", headers=tokens["consultor.rj02"])
    lead = random.choice(["L-1001", "L-1002", "L-1003"])
    clients["consultor.sp01"].patch(f"/api/v1/leads/{lead}", headers=tokens["consultor.sp01"],
                                    json={"status": random.choice(["contatado", "agendado"])})
    clients["gestor.sp01"].get("/api/v1/dealers/SP01/service-share", headers=tokens["gestor.sp01"])
    for _ in range(random.randint(4, 9)):
        clients["gestor.sp01"].post("/api/v1/predictions/churn", headers=tokens["gestor.sp01"], json={
            "model": random.choice(["Ranger", "Territory", "Maverick", "Transit", "Bronco Sport"]),
            "vehicle_age_years": random.randint(0, 10),
            "km_since_last_service": random.randint(1000, 30000),
            "months_since_last_visit": random.randint(0, 24),
            "services_last_24m": random.randint(0, 4),
            "warranty_active": random.random() < 0.5,
            "connected_vehicle": random.random() < 0.6,
        })
    if random.random() < 0.3:  # usuário legítimo errando a senha de vez em quando
        clients["consultor.rj02"].post("/api/v1/auth/login",
                                       json={"username": "consultor.rj02", "password": "senha-digitada-errada"})


def main() -> None:
    tokens = {u: login(u) for u in USERS}
    series = []
    prev = snapshot()
    for tick in range(24):
        normal_traffic(tokens)
        telemetry(tick)
        if tick in (4, 5, 6, 7):  # aparelho que nunca atualizou o app
            for _ in range(4):
                old_app.get("/api/v1/dealers/SP01/leads")
        if tick in (8, 9, 10):
            for i in range(40):
                attacker.post("/api/v1/auth/login",
                              json={"username": "gestor.sp01", "password": f"Senha{tick}{i:03d}!ab"})
        if tick in (14, 15, 16):
            h = tokens["consultor.rj02"]
            for lead in ("L-1001", "L-1002", "L-1003", "L-1004", "L-1005"):
                clients["consultor.rj02"].get(f"/api/v1/leads/{lead}", headers=h)
            for _ in range(4):
                clients["consultor.rj02"].get("/api/v1/dealers/SP01/leads", headers=h)
        if tick == 19:
            forged = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
            for _ in range(25):
                attacker.get("/api/v1/admin/audit-events",
                             headers={"Authorization": f"Bearer {forged}.eyJzdWIiOiJ4In0."})
        if tick == 12:  # login periódico: tokens expiram em 15 min
            tokens = {u: login(u) for u in USERS}

        current = snapshot()
        series.append({"tick": tick, "delta": {k: current[k] - prev.get(k, 0.0)
                                               for k in current if current[k] - prev.get(k, 0.0)}})
        prev = current

    OUT_SERIES.write_text(json.dumps(series, indent=1), encoding="utf-8")
    file_handler.close()
    print(f"Logs:    {OUT_LOGS} ({sum(1 for _ in open(OUT_LOGS, encoding='utf-8'))} linhas)")
    print(f"Métricas: {OUT_SERIES} ({len(series)} intervalos)")


if __name__ == "__main__":
    main()
