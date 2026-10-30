"""Testes da interface de linha de comando simulando o que o usuário digita."""
import pytest

from keynest import cli, clipboard
from keynest.vault import Entry, Vault

FAST_KDF = {"name": "argon2id", "time_cost": 1, "memory_cost": 1024, "parallelism": 1}
MASTER = "Senha-Mestra-De-Teste-42"


@pytest.fixture
def env(tmp_path, monkeypatch):
    path = tmp_path / "vault.json"
    vault = Vault.create(path, MASTER, kdf=FAST_KDF)
    vault.add(Entry(name="github", username="knx", password="gh-pass", totp="JBSWY3DPEHPK3PXP"))
    vault.add(Entry(name="semurl", username="eu", password="x"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": MASTER)
    monkeypatch.setattr("builtins.input", lambda prompt="": "s")
    copied = []
    monkeypatch.setattr(clipboard, "copy", lambda text: copied.append(text) or True)
    monkeypatch.setattr(clipboard, "clear_later", lambda text, seconds: None)
    return path, copied


def run(path, *argv):
    cli.main(["--vault", str(path), *argv])


def test_get_copies_password(env, capsys):
    path, copied = env
    run(path, "get", "github")
    assert copied == ["gh-pass"]
    assert "gh-pass" not in capsys.readouterr().out  # Sem -s a senha não aparece na tela


def test_get_field_errors(env, capsys):
    path, copied = env
    with pytest.raises(SystemExit):
        run(path, "get", "semurl", "-f", "totp")
    with pytest.raises(SystemExit):
        run(path, "get", "semurl", "-f", "url")
    assert copied == []
    run(path, "get", "github", "-f", "totp", "-s")
    assert capsys.readouterr().out.strip().isdigit()


def test_import_csv_with_invalid_totp(env, tmp_path, capsys):
    path, _ = env
    csv_file = tmp_path / "export.csv"
    csv_file.write_text("name,url,username,password,totp\n"
                        "site,https://site.com,ana,s1,isso-nao-e-base32!\n"
                        "github,https://github.com,outro,s2,\n"
                        "vazio,https://v.com,ana,,\n", encoding="utf-8")
    run(path, "import", str(csv_file))
    assert "2 entrada(s) importada(s), 1 ignorada(s)" in capsys.readouterr().out

    vault = Vault.open(path, MASTER)
    site = vault.get("site")
    assert site.totp == "" and "TOTP: isso-nao-e-base32!" in site.notes
    assert vault.get("github (2)").username == "outro"


def test_wrong_master_password(env, monkeypatch, capsys):
    path, _ = env
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "errada")
    with pytest.raises(SystemExit) as exit_info:
        run(path, "ls")
    assert exit_info.value.code == 1
    assert "Senha mestra incorreta" in capsys.readouterr().err
