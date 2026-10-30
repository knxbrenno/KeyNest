import json

import pytest

from keynest import crypto
from keynest.vault import AmbiguousEntry, Entry, EntryNotFound, Vault

# Parâmetros leves para os testes rodarem rápido (o padrão usa 64 MiB).
FAST_KDF = {"name": "argon2id", "time_cost": 1, "memory_cost": 1024, "parallelism": 1}


@pytest.fixture
def vault(tmp_path):
    return Vault.create(tmp_path / "vault.json", "senha-mestra-forte", kdf=FAST_KDF)


def test_roundtrip(vault):
    vault.add(Entry(name="GitHub", username="knx", password="s3nh@!", tags=["dev"]))
    reopened = Vault.open(vault.path, "senha-mestra-forte")
    assert reopened.get("github").password == "s3nh@!"
    assert reopened.get("github").tags == ["dev"]


def test_file_does_not_contain_plaintext(vault):
    vault.add(Entry(name="Banco", username="joao", password="SegredoSuperUnico123"))
    content = vault.path.read_text()
    assert "SegredoSuperUnico123" not in content
    assert "joao" not in content
    assert "Banco" not in content


def test_wrong_password(vault):
    with pytest.raises(crypto.WrongPasswordError):
        Vault.open(vault.path, "senha-errada")


def test_tampering_is_detected(vault):
    vault.add(Entry(name="x", password="y"))
    document = json.loads(vault.path.read_text())
    ciphertext = bytearray(crypto.b64d(document["ciphertext"]))
    ciphertext[0] ^= 1
    document["ciphertext"] = crypto.b64e(bytes(ciphertext))
    vault.path.write_text(json.dumps(document))
    with pytest.raises(crypto.WrongPasswordError):
        Vault.open(vault.path, "senha-mestra-forte")


def test_header_tampering_is_detected(vault):
    document = json.loads(vault.path.read_text())
    document["kdf"]["time_cost"] = 2  # Mesmo com a senha certa, o cabeçalho é autenticado
    vault.path.write_text(json.dumps(document))
    with pytest.raises(crypto.WrongPasswordError):
        Vault.open(vault.path, "senha-mestra-forte")


def test_nonce_changes_every_save(vault):
    first = json.loads(vault.path.read_text())["nonce"]
    vault.add(Entry(name="a", password="b"))
    assert json.loads(vault.path.read_text())["nonce"] != first


def test_change_master_password(vault):
    vault.add(Entry(name="a", password="b"))
    vault.change_master_password("nova-senha-mestra")
    assert Vault.open(vault.path, "nova-senha-mestra").get("a").password == "b"
    with pytest.raises(crypto.WrongPasswordError):
        Vault.open(vault.path, "senha-mestra-forte")
    assert not vault.path.with_suffix(".bak").exists()


def test_password_history(vault):
    entry = vault.add(Entry(name="email", password="antiga"))
    vault.update(entry, password="nova")
    assert entry.password == "nova"
    assert entry.history[0]["password"] == "antiga"


def test_get_search_and_duplicates(vault):
    vault.add(Entry(name="github-pessoal", password="1"))
    vault.add(Entry(name="github-trabalho", password="2"))
    vault.add(Entry(name="gmail", username="eu@gmail.com", password="3", tags=["email"]))
    assert vault.get("pessoal").password == "1"
    with pytest.raises(AmbiguousEntry):
        vault.get("github")
    with pytest.raises(EntryNotFound):
        vault.get("nao-existe")
    with pytest.raises(ValueError):
        vault.add(Entry(name="GMAIL", password="x"))
    assert [e.name for e in vault.find("gmail.com")] == ["gmail"]
    assert [e.name for e in vault.find(tag="email")] == ["gmail"]
