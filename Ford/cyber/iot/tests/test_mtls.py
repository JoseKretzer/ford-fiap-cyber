"""Teste real de handshake mTLS com a mesma política do broker (TLS >= 1.2, certificado de
cliente obrigatório, CA própria) e o mesmo contexto TLS do dispositivo (telemetry_publisher).

A PKI é gerada no teste com `cryptography` (equivalente ao gerar_certificados.ps1).
"""
import datetime as dt
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telemetry_publisher import build_tls_context  # noqa: E402

DEVICE = "veh-3f9a1c2b7d0e4a18"


def _write(path: Path, key, cert):
    path.with_suffix(".key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    path.with_suffix(".crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _cert(cn, issuer_key, issuer_name, key, *, ca=False, san=None, eku=None):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(issuer_name or x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         # SKI/AKI: exigidos pela verificação X.509 estrita (padrão no Python 3.13+)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                        critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def _make_ca(folder: Path, name: str):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _cert(name, key, None, key, ca=True)
    _write(folder / "ca", key, cert)
    return key, cert


@pytest.fixture
def pki(tmp_path):
    good = tmp_path / "good"
    rogue = tmp_path / "rogue"
    good.mkdir(); rogue.mkdir()
    ca_key, ca = _make_ca(good, "VINShare-IoT-CA")
    for name, san, eku in (("broker", ["localhost", "mosquitto"], ExtendedKeyUsageOID.SERVER_AUTH),
                           ("broker-sem-san", None, ExtendedKeyUsageOID.SERVER_AUTH),
                           (DEVICE, None, ExtendedKeyUsageOID.CLIENT_AUTH)):
        key = ec.generate_private_key(ec.SECP256R1())
        _write(good / name, key, _cert(name, ca_key, ca.subject, key, san=san, eku=eku))
    # CA de um atacante emitindo um certificado com o MESMO CN do veículo
    rca_key, rca = _make_ca(rogue, "CA-Falsa")
    key = ec.generate_private_key(ec.SECP256R1())
    _write(rogue / DEVICE, key, _cert(DEVICE, rca_key, rca.subject, key, eku=ExtendedKeyUsageOID.CLIENT_AUTH))
    (rogue / "ca.crt").write_bytes((good / "ca.crt").read_bytes())  # o atacante confia na CA real do broker
    return good, rogue


def _broker(pki_dir: Path, cert_name="broker"):
    """Servidor TLS com a política do mosquitto.conf: TLS >= 1.2 e require_certificate true."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(pki_dir / "ca.crt")
    ctx.load_cert_chain(pki_dir / f"{cert_name}.crt", pki_dir / f"{cert_name}.key")
    srv = socket.create_server(("127.0.0.1", 0))
    result = {}

    def serve():
        conn, _ = srv.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                result["client_cn"] = dict(x[0] for x in tls.getpeercert()["subject"])["commonName"]
                result["version"] = tls.version()
                tls.sendall(b"ok")
        except (ssl.SSLError, OSError) as exc:
            result["error"] = type(exc).__name__

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return srv.getsockname()[1], result, t, srv


def _connect(port, ctx, hostname="localhost"):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            return tls.recv(2)


def test_device_with_valid_certificate_connects(pki):
    good, _ = pki
    port, result, t, srv = _broker(good)
    assert _connect(port, build_tls_context(str(good), DEVICE)) == b"ok"
    t.join(5); srv.close()
    assert result["client_cn"] == DEVICE          # o broker usa o CN como usuário na ACL
    assert result["version"] in ("TLSv1.2", "TLSv1.3")


def test_certificate_from_rogue_ca_is_rejected(pki):
    good, rogue = pki
    port, result, t, srv = _broker(good)
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        _connect(port, build_tls_context(str(rogue), DEVICE)).decode()
    t.join(5); srv.close()
    assert "client_cn" not in result


def test_broker_without_matching_san_is_rejected_by_device(pki):
    good, _ = pki
    port, result, t, srv = _broker(good, cert_name="broker-sem-san")
    with pytest.raises(ssl.SSLCertVerificationError):
        _connect(port, build_tls_context(str(good), DEVICE))
    t.join(5); srv.close()


def test_hostname_mismatch_is_rejected(pki):
    good, _ = pki
    port, result, t, srv = _broker(good)
    with pytest.raises(ssl.SSLCertVerificationError):
        _connect(port, build_tls_context(str(good), DEVICE), hostname="broker-falso.example")
    t.join(5); srv.close()


def test_client_without_certificate_is_rejected(pki):
    good, _ = pki
    port, result, t, srv = _broker(good)
    ctx = ssl.create_default_context(cafile=str(good / "ca.crt"))  # sem load_cert_chain
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        _connect(port, ctx).decode()
    t.join(5); srv.close()
    assert "client_cn" not in result
