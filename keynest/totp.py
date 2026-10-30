"""Códigos de autenticação em dois fatores (TOTP, RFC 6238), compatíveis com Google Authenticator."""
import base64
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, urlparse

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def parse(value):
    """
    Aceita o segredo em Base32 ou uma URI otpauth:// (o conteúdo do QR Code).
    Retorna (segredo, dígitos, período, algoritmo).
    """
    value = value.strip()
    if value.lower().startswith("otpauth://"):
        params = {k.lower(): v[0] for k, v in parse_qs(urlparse(value).query).items()}
        return (normalize(params["secret"]), int(params.get("digits", 6)), int(params.get("period", 30)),
                params.get("algorithm", "SHA1").upper())
    return normalize(value), 6, 30, "SHA1"


def normalize(secret):
    secret = secret.replace(" ", "").replace("-", "").upper()
    base64.b32decode(secret + "=" * (-len(secret) % 8))  # Valida (levanta erro se inválido)
    return secret


def generate(value, at=None):
    secret, digits, period, algorithm = parse(value)
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = int((time.time() if at is None else at) // period)
    mac = hmac.new(key, struct.pack(">Q", counter), ALGORITHMS[algorithm]).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** digits
    return str(code).zfill(digits)


def seconds_remaining(value, at=None):
    period = parse(value)[2]
    return period - int(time.time() if at is None else at) % period
