"""Criptografia local de dados pessoais (LGPD art. 46).

- AES-256-GCM (cifra autenticada): garante confidencialidade e integridade.
  Qualquer alteração no texto cifrado é detectada na decifragem.
- Nonce aleatório de 96 bits por operação (nunca reutilizado).
- O ID da chave vai junto do dado ("k1:<base64>") para permitir rotação:
  dados antigos continuam legíveis enquanto são recifrados com a chave nova.
- HMAC-SHA256 como "índice cego": permite buscar um cliente pelo CPF sem
  guardar o CPF em claro e sem precisar decifrar a base inteira.
"""
import base64
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(Exception):
    pass


class FieldCipher:
    def __init__(self, keys: dict[str, bytes], active_key_id: str, index_key: bytes):
        if active_key_id not in keys:
            raise ValueError("Chave ativa não encontrada no keyring")
        self._keys = {kid: AESGCM(k) for kid, k in keys.items()}
        self._active = active_key_id
        self._index_key = index_key

    def encrypt(self, plaintext: str, context: str) -> str:
        """Cifra um campo. `context` (ex.: 'customer.cpf') entra como AAD:
        um valor cifrado de um campo não pode ser copiado para outro."""
        nonce = os.urandom(12)
        ct = self._keys[self._active].encrypt(nonce, plaintext.encode(), context.encode())
        return f"{self._active}:{base64.b64encode(nonce + ct).decode()}"

    def decrypt(self, token: str, context: str) -> str:
        try:
            kid, payload = token.split(":", 1)
            raw = base64.b64decode(payload)
            return self._keys[kid].decrypt(raw[:12], raw[12:], context.encode()).decode()
        except (ValueError, KeyError, InvalidTag) as exc:
            # Falha fechada: nunca devolve dado parcial ou adulterado
            raise DecryptionError("Falha ao decifrar campo protegido") from exc

    def blind_index(self, value: str) -> str:
        normalized = "".join(ch for ch in value if ch.isalnum()).upper()
        return hmac.new(self._index_key, b"idx:" + normalized.encode(), hashlib.sha256).hexdigest()


def mask_cpf(cpf: str) -> str:
    digits = "".join(ch for ch in cpf if ch.isdigit())
    return f"***.***.***-{digits[-2:]}" if len(digits) == 11 else "***"


def mask_phone(phone: str) -> str:
    digits = "".join(ch for ch in phone if ch.isdigit())
    return f"(**) *****-{digits[-4:]}" if len(digits) >= 4 else "***"


def pseudonymize_vin(vin: str, index_key: bytes) -> str:
    """VIN ligado a um proprietário é dado pessoal. Para analytics/ML/IoT usamos
    um pseudônimo estável e não reversível sem a chave. O prefixo "vin:" separa o
    domínio deste HMAC do índice cego de CPF, que usa a mesma chave."""
    return "veh-" + hmac.new(index_key, b"vin:" + vin.upper().encode(), hashlib.sha256).hexdigest()[:16]
