"""
Criptografia do cofre.

- A chave de 256 bits é derivada da senha mestra com Argon2id (resistente a ataques com GPU).
- O conteúdo é cifrado com AES-256-GCM, que também detecta qualquer alteração no arquivo.
- O cabeçalho (parâmetros do Argon2 e salt) é autenticado como "dados associados" (AAD),
  então ninguém consegue trocar os parâmetros sem que a abertura do cofre falhe.
"""
import base64
import json
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = "keynest"
VERSION = 1
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

# 3 iterações e 64 MiB de memória: cerca de 0,3 s por tentativa num PC comum.
DEFAULT_KDF = {"name": "argon2id", "time_cost": 3, "memory_cost": 64 * 1024, "parallelism": 4}


class WrongPasswordError(Exception):
    """Senha mestra incorreta ou arquivo do cofre adulterado."""


class VaultFormatError(Exception):
    """O arquivo não é um cofre válido do KeyNest."""


def b64e(data):
    return base64.b64encode(data).decode()


def b64d(text):
    return base64.b64decode(text)


def new_header(kdf=None):
    params = dict(kdf or DEFAULT_KDF)
    params["salt"] = b64e(os.urandom(SALT_LEN))
    return {"format": FORMAT, "version": VERSION, "kdf": params}


def derive_key(password, header):
    kdf = header["kdf"]
    if kdf.get("name") != "argon2id":
        raise VaultFormatError(f"Algoritmo de derivação não suportado: {kdf.get('name')}")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=b64d(kdf["salt"]),
        time_cost=kdf["time_cost"],
        memory_cost=kdf["memory_cost"],
        parallelism=kdf["parallelism"],
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def _aad(header):
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


def seal(payload, key, header):
    """Cifra um dicionário e devolve o documento pronto para salvar em disco."""
    nonce = os.urandom(NONCE_LEN)  # Nonce novo a cada gravação
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad(header))
    return {**header, "nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}


def split_document(document):
    """Separa o documento salvo em (cabeçalho, nonce, texto cifrado), validando o formato."""
    try:
        if document["format"] != FORMAT:
            raise VaultFormatError("O arquivo não é um cofre do KeyNest.")
        if document["version"] > VERSION:
            raise VaultFormatError("Cofre criado por uma versão mais nova do KeyNest.")
        header = {"format": document["format"], "version": document["version"], "kdf": document["kdf"]}
        return header, b64d(document["nonce"]), b64d(document["ciphertext"])
    except (KeyError, TypeError, ValueError) as err:
        raise VaultFormatError(f"Arquivo do cofre corrompido: {err}") from err


def unseal(document, key):
    header, nonce, ciphertext = split_document(document)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, _aad(header))
    except InvalidTag:
        raise WrongPasswordError("Senha mestra incorreta (ou o arquivo foi alterado).") from None
    return json.loads(plaintext.decode("utf-8"))
