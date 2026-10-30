"""Cofre: carrega, altera e salva as entradas de forma criptografada."""
import json
import os
import secrets
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import crypto

MAX_HISTORY = 10


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_vault_path():
    return Path(os.environ.get("KEYNEST_VAULT", Path.home() / ".keynest" / "vault.json"))


@dataclass
class Entry:
    name: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: list = field(default_factory=list)
    totp: str = ""
    id: str = field(default_factory=lambda: secrets.token_hex(4))
    created: str = field(default_factory=now)
    updated: str = field(default_factory=now)
    history: list = field(default_factory=list)  # Senhas anteriores: [{"password", "changed"}]

    @classmethod
    def from_dict(cls, data):
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


class EntryNotFound(Exception):
    pass


class AmbiguousEntry(Exception):
    def __init__(self, matches):
        self.matches = matches
        super().__init__("Mais de uma entrada corresponde: " + ", ".join(e.name for e in matches))


class Vault:
    def __init__(self, path, key, header, entries):
        self.path = Path(path)
        self._key = key
        self.header = header
        self.entries = entries

    # ------------------------------------------------------------------ abrir / salvar

    @classmethod
    def create(cls, path, master_password, kdf=None):
        path = Path(path)
        if path.exists():
            raise FileExistsError(f"Já existe um cofre em {path}")
        header = crypto.new_header(kdf)
        vault = cls(path, crypto.derive_key(master_password, header), header, [])
        vault.save()
        return vault

    @classmethod
    def open(cls, path, master_password):
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Nenhum cofre encontrado em {path}. Crie um com: keynest init")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as err:
            raise crypto.VaultFormatError(f"Arquivo do cofre corrompido: {err}") from err
        header, _, _ = crypto.split_document(document)
        key = crypto.derive_key(master_password, header)
        payload = crypto.unseal(document, key)
        return cls(path, key, header, [Entry.from_dict(e) for e in payload.get("entries", [])])

    def save(self):
        """Gravação atômica: escreve num arquivo temporário e só então substitui o cofre."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = crypto.seal({"entries": [asdict(e) for e in self.entries]}, self._key, self.header)

        if self.path.exists():
            shutil.copy2(self.path, self.path.with_suffix(".bak"))

        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".vault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(document, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def change_master_password(self, new_password):
        self.header = crypto.new_header(self.header["kdf"])  # Novo salt
        self._key = crypto.derive_key(new_password, self.header)
        self.save()
        # O backup ainda abriria com a senha antiga; se ela vazou, ele não pode continuar existindo.
        self.path.with_suffix(".bak").unlink(missing_ok=True)

    def lock(self):
        self._key = None
        self.entries = []

    # ------------------------------------------------------------------ entradas

    def find(self, query="", tag=None):
        query = query.lower()
        result = []
        for e in self.entries:
            if tag and tag.lower() not in (t.lower() for t in e.tags):
                continue
            if not query or any(query in v.lower() for v in (e.name, e.username, e.url, e.notes, *e.tags)):
                result.append(e)
        return sorted(result, key=lambda e: e.name.lower())

    def get(self, name_or_id):
        """Busca por nome exato, ID ou, se não houver, por trecho único do nome."""
        key = name_or_id.lower()
        for e in self.entries:
            if e.name.lower() == key or e.id == key:
                return e
        partial = [e for e in self.entries if key in e.name.lower()]
        if len(partial) == 1:
            return partial[0]
        if len(partial) > 1:
            raise AmbiguousEntry(partial)
        raise EntryNotFound(f"Entrada '{name_or_id}' não encontrada.")

    def add(self, entry):
        if any(e.name.lower() == entry.name.lower() for e in self.entries):
            raise ValueError(f"Já existe uma entrada chamada '{entry.name}'.")
        self.entries.append(entry)
        self.save()
        return entry

    def update(self, entry, **fields):
        if "name" in fields and fields["name"].lower() != entry.name.lower():
            if any(e.name.lower() == fields["name"].lower() for e in self.entries):
                raise ValueError(f"Já existe uma entrada chamada '{fields['name']}'.")
        if "password" in fields and fields["password"] != entry.password and entry.password:
            entry.history.insert(0, {"password": entry.password, "changed": now()})
            del entry.history[MAX_HISTORY:]
        for name, value in fields.items():
            setattr(entry, name, value)
        entry.updated = now()
        self.save()
        return entry

    def delete(self, entry):
        self.entries.remove(entry)
        self.save()
