"""Simulador do módulo telemático do veículo: publica telemetria via MQTT sobre TLS (mTLS).

Minimização (LGPD): só envia o que o modelo de churn usa (odômetro, códigos de falha,
vida do óleo). Localização GPS NÃO é enviada.
"""
import json
import os
import ssl
import time
import uuid


def build_tls_context(cert_dir: str, device_id: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{cert_dir}/ca.crt")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True                 # evita MITM com certificado de outro host
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(f"{cert_dir}/{device_id}.crt", f"{cert_dir}/{device_id}.key")
    return ctx


def telemetry_payload(odometer_km: int, dtc_codes: list[str], oil_life_pct: int) -> str:
    return json.dumps({
        "msg_id": uuid.uuid4().hex,            # a ingestão descarta msg_id repetido (anti-replay)
        "ts": int(time.time()),                # a ingestão rejeita mensagens com mais de 5 min
        "odometer_km": odometer_km,
        "dtc_codes": dtc_codes[:10],
        "oil_life_pct": oil_life_pct,
    })


def main() -> None:  # pragma: no cover - depende do broker em execução
    import paho.mqtt.client as mqtt

    device_id = os.environ["DEVICE_ID"]       # pseudônimo do VIN, igual ao CN do certificado
    cert_dir = os.environ.get("CERT_DIR", "iot/certs")
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=device_id, protocol=mqtt.MQTTv5)
    client.tls_set_context(build_tls_context(cert_dir, device_id))
    client.connect(os.environ.get("MQTT_HOST", "localhost"), 8883, keepalive=60)
    client.loop_start()
    info = client.publish(f"vehicles/{device_id}/telemetry", telemetry_payload(48210, ["P0420"], 23), qos=1)
    info.wait_for_publish(timeout=10)
    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
