"""Testes de segurança da ingestão de telemetria (anti-replay, esquema, janela de tempo)."""
import json
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ingestion import TelemetryValidator  # noqa: E402

NOW = 1_790_000_000
TOPIC = "vehicles/veh-3f9a1c2b7d0e4a18/telemetry"


def msg(**over) -> bytes:
    body = {"msg_id": uuid.uuid4().hex, "ts": NOW, "odometer_km": 48210, "dtc_codes": ["P0420"], "oil_life_pct": 23}
    body.update(over)
    return json.dumps(body).encode()


@pytest.fixture
def v():
    return TelemetryValidator()


def test_valid_message_accepted(v):
    ok, reason, record = v.validate(TOPIC, msg(), now=NOW)
    assert ok and reason == "aceita" and record["device_id"] == "veh-3f9a1c2b7d0e4a18"


def test_replay_rejected(v):
    payload = msg()
    assert v.validate(TOPIC, payload, now=NOW)[0]
    assert v.validate(TOPIC, payload, now=NOW + 10)[1] == "replay"


def test_same_msg_id_other_device_is_not_replay(v):
    payload = msg()
    assert v.validate(TOPIC, payload, now=NOW)[0]
    assert v.validate("vehicles/veh-0000000000000001/telemetry", payload, now=NOW)[0]


@pytest.mark.parametrize("ts,reason", [(NOW - 301, "mensagem_antiga"), (NOW + 31, "timestamp_futuro")])
def test_time_window(v, ts, reason):
    assert v.validate(TOPIC, msg(ts=ts), now=NOW)[1] == reason


@pytest.mark.parametrize("topic", [
    "vehicles/veh-3f9a1c2b7d0e4a18/commands",
    "vehicles/+/telemetry",
    "vehicles/VIN9BFZH54P0R8123456/telemetry",
    "vehicles/veh-3f9a1c2b7d0e4a18/telemetry/extra",
])
def test_invalid_topic(v, topic):
    assert v.validate(topic, msg(), now=NOW)[1] == "topico_invalido"


@pytest.mark.parametrize("payload", [
    msg(extra="x"),
    msg(odometer_km=-1),
    msg(odometer_km="48210"),
    msg(oil_life_pct=101),
    msg(dtc_codes=["P0420; DROP TABLE"]),
    msg(dtc_codes=["P0420"] * 11),
    msg(msg_id="abc"),
    msg(ts=float(NOW)),
    json.dumps([1, 2, 3]).encode(),
], ids=["campo_extra", "odometro_negativo", "tipo_errado", "oleo_fora_faixa", "dtc_injecao",
        "dtc_demais", "msg_id_invalido", "ts_float", "nao_objeto"])
def test_schema_violations(v, payload):
    assert v.validate(TOPIC, payload, now=NOW)[1] == "esquema_invalido"


def test_invalid_json(v):
    assert v.validate(TOPIC, b"\xff{not json", now=NOW)[1] == "json_invalido"


def test_oversized_payload(v):
    assert v.validate(TOPIC, b"{" + b" " * 5000 + b"}", now=NOW)[1] == "payload_grande"


def test_odometer_regression_flagged(v):
    assert v.validate(TOPIC, msg(odometer_km=50000), now=NOW)[0]
    assert v.validate(TOPIC, msg(odometer_km=10000), now=NOW + 60)[1] == "odometro_regrediu"


def test_replay_cache_expires(v):
    payload = msg(ts=NOW)
    assert v.validate(TOPIC, payload, now=NOW)[0]
    # depois do TTL, a mensagem já cai na janela de tempo (proteção em camadas)
    assert v.validate(TOPIC, payload, now=NOW + 1000)[1] == "mensagem_antiga"


def test_metrics_count_each_result(v):
    v.validate(TOPIC, msg(), now=NOW)
    v.validate("bad/topic", msg(), now=NOW)
    assert v.registry.get_sample_value("vinshare_iot_messages_total", {"result": "aceita"}) == 1
    assert v.registry.get_sample_value("vinshare_iot_messages_total", {"result": "topico_invalido"}) == 1
