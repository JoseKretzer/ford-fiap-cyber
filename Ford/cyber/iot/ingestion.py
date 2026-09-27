"""Serviço de ingestão da telemetria veicular (broker MQTT -> VIN Share).

A telemetria vem de dispositivos em campo e é tratada como NÃO CONFIÁVEL
(OWASP API10 - Unsafe Consumption). Antes de gravar, cada mensagem passa por:
  1. tópico no formato vehicles/<pseudônimo>/telemetry (a ACL do broker garante
     que o dispositivo só publica no próprio tópico)
  2. tamanho máximo de 4 KB
  3. esquema estrito (campos, tipos e faixas; campos extras são rejeitados)
  4. janela de tempo: mais de 5 min no passado ou 30 s no futuro é rejeitado
  5. anti-replay: (dispositivo, msg_id) já visto é rejeitado
  6. coerência: odômetro não pode regredir (sinal de adulteração)
Cada decisão vira métrica (vinshare_iot_messages_total{result}) e as rejeições
viram log JSON de auditoria, o que alimenta o alerta TelemetriaRejeitada (PB-04).
"""
import json
import logging
import os
import re
import ssl
import sys
import time

from prometheus_client import CollectorRegistry, Counter, Gauge, start_http_server

TOPIC = re.compile(r"^vehicles/(veh-[0-9a-f]{16})/telemetry$")
MSG_ID = re.compile(r"^[0-9a-f]{32}$")
DTC = re.compile(r"^[PCBU][0-9A-F]{4}$")
FIELDS = {"msg_id", "ts", "odometer_km", "dtc_codes", "oil_life_pct"}
MAX_PAYLOAD = 4096

class _JsonFormatter(logging.Formatter):
    """Uma linha JSON plana por evento (mesmo formato da API, lido pelo Loki com `| json`)."""
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"), "level": record.levelname,
                           "logger": record.name, "event": record.getMessage(), **getattr(record, "fields", {})})


log = logging.getLogger("vinshare.iot")
if not log.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    log.addHandler(handler)
    log.setLevel(logging.INFO)


class TelemetryValidator:
    def __init__(self, registry: CollectorRegistry | None = None, max_age_s: int = 300,
                 max_future_s: int = 30, replay_ttl_s: int = 900):
        self.registry = registry or CollectorRegistry()
        self.max_age = max_age_s
        self.max_future = max_future_s
        self.replay_ttl = replay_ttl_s
        self._seen: dict[tuple[str, str], float] = {}     # em produção: Redis SET NX com TTL
        self._odometer: dict[str, int] = {}
        self.messages = Counter("vinshare_iot_messages_total", "Mensagens de telemetria por resultado",
                                ["result"], registry=self.registry)
        self.last_accepted = Gauge("vinshare_iot_last_accepted_timestamp_seconds",
                                   "Horário da última telemetria aceita", registry=self.registry)

    def _reject(self, reason: str, device: str | None) -> tuple[bool, str, None]:
        self.messages.labels(result=reason).inc()
        log.warning("iot.telemetry.rejected", extra={"fields": {"reason": reason, "device_id": device}})
        return False, reason, None

    def validate(self, topic: str, payload: bytes, now: float | None = None):
        now = time.time() if now is None else now
        m = TOPIC.match(topic)
        if not m:
            return self._reject("topico_invalido", None)
        device = m.group(1)
        if len(payload) > MAX_PAYLOAD:
            return self._reject("payload_grande", device)
        try:
            data = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            return self._reject("json_invalido", device)

        if not (isinstance(data, dict) and set(data) == FIELDS
                and isinstance(data["msg_id"], str) and MSG_ID.match(data["msg_id"])
                and type(data["ts"]) is int
                and type(data["odometer_km"]) is int and 0 <= data["odometer_km"] <= 2_000_000
                and type(data["oil_life_pct"]) is int and 0 <= data["oil_life_pct"] <= 100
                and isinstance(data["dtc_codes"], list) and len(data["dtc_codes"]) <= 10
                and all(isinstance(c, str) and DTC.match(c) for c in data["dtc_codes"])):
            return self._reject("esquema_invalido", device)

        if data["ts"] < now - self.max_age:
            return self._reject("mensagem_antiga", device)
        if data["ts"] > now + self.max_future:
            return self._reject("timestamp_futuro", device)

        self._seen = {k: t for k, t in self._seen.items() if t > now - self.replay_ttl}
        key = (device, data["msg_id"])
        if key in self._seen:
            return self._reject("replay", device)

        if data["odometer_km"] < self._odometer.get(device, 0):
            return self._reject("odometro_regrediu", device)

        self._seen[key] = now
        self._odometer[device] = data["odometer_km"]
        self.messages.labels(result="aceita").inc()
        self.last_accepted.set(now)
        return True, "aceita", {"device_id": device, **data}


def main() -> None:  # pragma: no cover - depende do broker em execução
    import paho.mqtt.client as mqtt

    cert_dir = os.environ.get("CERT_DIR", "/certs")
    validator = TelemetryValidator()
    start_http_server(int(os.environ.get("METRICS_PORT", "9101")), registry=validator.registry)

    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{cert_dir}/ca.crt")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(f"{cert_dir}/ingestion-service.crt", f"{cert_dir}/ingestion-service.key")

    def on_connect(client, userdata, flags, reason_code, properties):
        client.subscribe("vehicles/+/telemetry", qos=1)

    def on_message(client, userdata, msg):
        ok, reason, record = validator.validate(msg.topic, msg.payload)
        if ok:
            log.info("iot.telemetry.accepted", extra={"fields": {"device_id": record["device_id"]}})
            # aqui: gravação no banco (odômetro/DTC alimentam as features do modelo de churn)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="ingestion-service", protocol=mqtt.MQTTv5)
    client.tls_set_context(ctx)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(os.environ.get("MQTT_HOST", "mosquitto"), 8883, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    main()
