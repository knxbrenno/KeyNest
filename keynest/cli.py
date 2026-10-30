"""Interface de linha de comando do KeyNest."""
import argparse
import csv
import getpass
import json
import os
import shlex
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, clipboard, generator, pwned, strength, totp
from .crypto import VaultFormatError, WrongPasswordError
from .vault import AmbiguousEntry, Entry, EntryNotFound, Vault, default_vault_path

CLIPBOARD_SECONDS = 20
AUTO_LOCK_MINUTES = 5
OLD_PASSWORD_DAYS = 365

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
if USE_COLOR and sys.platform == "win32":
    os.system("")  # Ativa os códigos de cor ANSI no console do Windows


def color(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def green(t): return color(t, "32")
def yellow(t): return color(t, "33")
def red(t): return color(t, "31")
def bold(t): return color(t, "1")
def dim(t): return color(t, "2")


SCORE_COLORS = [red, red, yellow, green, green]


class CLIError(Exception):
    pass


# ---------------------------------------------------------------------- utilitários

def ask_password(prompt="Senha mestra: "):
    return getpass.getpass(prompt)


def ask_new_password(prompt, allow_empty=False):
    while True:
        first = getpass.getpass(prompt)
        if not first and allow_empty:
            return ""
        if getpass.getpass("Confirme: ") == first:
            return first
        print(red("As senhas não coincidem. Tente de novo."))


def confirm(question):
    return input(f"{question} [s/N] ").strip().lower() in ("s", "sim", "y", "yes")


def open_vault(args):
    if getattr(args, "vault_obj", None):
        return args.vault_obj
    try:
        return Vault.open(args.vault, ask_password())
    except WrongPasswordError as err:
        raise CLIError(str(err)) from None


def resolve(vault, name):
    try:
        return vault.get(name)
    except EntryNotFound as err:
        raise CLIError(str(err)) from None
    except AmbiguousEntry as err:
        raise CLIError(f"{err}. Seja mais específico.") from None


def copy_to_clipboard(text, what="Senha"):
    if clipboard.copy(text):
        clipboard.clear_later(text, CLIPBOARD_SECONDS)
        print(green(f"{what} copiada. A área de transferência será limpa em {CLIPBOARD_SECONDS}s."))
        return True
    print(yellow("Área de transferência indisponível (instale xclip, xsel ou wl-clipboard). Use --show."))
    return False


def print_strength(password, check_pwned=True):
    result = strength.evaluate(password)
    paint = SCORE_COLORS[result["score"]]
    bar = "█" * (result["score"] + 1) + "░" * (4 - result["score"])
    print(f"Força:    {paint(bar)} {paint(result['label'])} ({result['entropy']} bits)")
    print(f"Quebra:   {strength.crack_time(result['entropy'])} (ataque offline com GPU)")
    for warning in result["warnings"]:
        print(yellow(f"  ! {warning}"))
    if check_pwned:
        try:
            count = pwned.pwned_count(password)
            if count:
                print(red(f"Vazada:   SIM, apareceu {count:,} vezes em vazamentos!".replace(",", ".")))
            else:
                print(green("Vazada:   não encontrada em vazamentos conhecidos."))
        except pwned.PwnedCheckError as err:
            print(dim(str(err)))


def build_password(args):
    """Gera ou pede a senha de uma entrada, de acordo com as opções -g/--passphrase."""
    if getattr(args, "passphrase", None):
        return generator.generate_passphrase(args.passphrase)
    if getattr(args, "generate", None):
        return generator.generate_password(args.generate, symbols=not args.no_symbols)
    password = ask_new_password("Senha da entrada (Enter para gerar uma): ", allow_empty=True)
    return password or generator.generate_password(20)


def parse_tags(text):
    return [t.strip() for t in text.split(",") if t.strip()] if text else []


def validate_totp(value):
    if not value:
        return ""
    try:
        totp.parse(value)
    except Exception:
        raise CLIError("Segredo TOTP inválido (use o código Base32 ou a URI otpauth://).") from None
    return value


# ---------------------------------------------------------------------- comandos

def cmd_init(args):
    if args.vault.exists():
        raise CLIError(f"Já existe um cofre em {args.vault}")
    print(bold("Criando um novo cofre KeyNest"))
    print("A senha mestra protege todas as outras. Ela NÃO pode ser recuperada se for esquecida.")
    print(dim("Dica: use uma frase-senha, ex.: " + generator.generate_passphrase(5)))
    while True:
        password = ask_new_password("Nova senha mestra: ")
        result = strength.evaluate(password)
        if result["score"] >= 3 or (result["score"] >= 2 and confirm(
                yellow(f"Senha {result['label'].lower()}. Usar mesmo assim?"))):
            break
        if result["score"] < 2:
            print(red(f"Senha {result['label'].lower()}: " + " ".join(result["warnings"])))
    Vault.create(args.vault, password)
    print(green(f"Cofre criado em {args.vault}"))


def cmd_add(args):
    vault = open_vault(args)
    entry = Entry(
        name=args.name,
        username=args.username if args.username is not None else input("Usuário: "),
        password=build_password(args),
        url=args.url or "",
        notes=args.notes or "",
        tags=parse_tags(args.tags),
        totp=validate_totp(args.totp),
    )
    try:
        vault.add(entry)
    except ValueError as err:
        raise CLIError(str(err)) from None
    print(green(f"Entrada '{entry.name}' adicionada."))
    result = strength.evaluate(entry.password)
    if result["score"] < 3:
        print(yellow(f"Atenção: senha {result['label'].lower()}."))
    if args.copy:
        copy_to_clipboard(entry.password)


def cmd_get(args):
    vault = open_vault(args)
    entry = resolve(vault, args.name)

    if args.field:
        if args.field == "totp":
            if not entry.totp:
                raise CLIError(f"A entrada '{entry.name}' não tem 2FA configurado.")
            value = totp.generate(entry.totp)
        else:
            value = getattr(entry, args.field)
        if not value:
            raise CLIError(f"O campo '{args.field}' de '{entry.name}' está vazio.")
        if args.show:
            print(value)
        else:
            copy_to_clipboard(value, args.field.capitalize())
        return

    print(bold(entry.name) + dim(f"  (id {entry.id})"))
    print(f"Usuário:  {entry.username}")
    print(f"Senha:    {entry.password if args.show else '•' * 12}")
    if entry.url:
        print(f"URL:      {entry.url}")
    if entry.tags:
        print(f"Tags:     {', '.join(entry.tags)}")
    if entry.totp:
        print(f"2FA:      {totp.generate(entry.totp)} (expira em {totp.seconds_remaining(entry.totp)}s)")
    if entry.notes:
        print(f"Notas:    {entry.notes}")
    print(dim(f"Criada em {entry.created[:10]}, alterada em {entry.updated[:10]}"
              + (f", {len(entry.history)} senha(s) anterior(es)" if entry.history else "")))
    if not args.show:
        copy_to_clipboard(entry.password)


def cmd_list(args):
    vault = open_vault(args)
    entries = vault.find(args.query or "", tag=args.tag)
    if not entries:
        print("Nenhuma entrada encontrada.")
        return
    width = max(len(e.name) for e in entries)
    user_width = max(len(e.username) for e in entries)
    for e in entries:
        flags = " 2FA" if e.totp else ""
        tags = dim(" [" + ", ".join(e.tags) + "]") if e.tags else ""
        print(f"{bold(e.name.ljust(width))}  {e.username.ljust(user_width)}  {dim(e.url)}{flags}{tags}")
    print(dim(f"\n{len(entries)} entrada(s)"))


def cmd_edit(args):
    vault = open_vault(args)
    entry = resolve(vault, args.name)
    fields = {}
    for name in ("username", "url", "notes"):
        if getattr(args, name) is not None:
            fields[name] = getattr(args, name)
    if args.new_name:
        fields["name"] = args.new_name
    if args.tags is not None:
        fields["tags"] = parse_tags(args.tags)
    if args.totp is not None:
        fields["totp"] = validate_totp(args.totp)
    if args.password or args.generate or args.passphrase:
        fields["password"] = build_password(args)
    if not fields:
        raise CLIError("Nada para alterar. Veja as opções com: keynest edit -h")
    try:
        vault.update(entry, **fields)
    except ValueError as err:
        raise CLIError(str(err)) from None
    print(green(f"Entrada '{entry.name}' atualizada: {', '.join(fields)}."))
    if "password" in fields and args.copy:
        copy_to_clipboard(entry.password)


def cmd_rm(args):
    vault = open_vault(args)
    entry = resolve(vault, args.name)
    if args.yes or confirm(f"Remover '{entry.name}' ({entry.username})?"):
        vault.delete(entry)
        print(green(f"Entrada '{entry.name}' removida."))


def cmd_gen(args):
    if args.passphrase:
        value = generator.generate_passphrase(args.passphrase, capitalize=args.capitalize,
                                              add_number=args.number)
        bits = generator.passphrase_entropy(args.passphrase)
    else:
        value = generator.generate_password(args.length, symbols=not args.no_symbols,
                                            exclude_ambiguous=args.no_ambiguous)
        bits = generator.password_entropy(args.length, symbols=not args.no_symbols)
    print(value)
    print(dim(f"{bits:.0f} bits de entropia, quebra em {strength.crack_time(bits)}"), file=sys.stderr)
    if args.copy:
        copy_to_clipboard(value)


def cmd_check(args):
    password = args.password if args.password is not None else getpass.getpass("Senha para verificar: ")
    print_strength(password, check_pwned=not args.offline)


def cmd_audit(args):
    vault = open_vault(args)
    if not vault.entries:
        print("O cofre está vazio.")
        return

    weak, old, pwned_list = [], [], []
    by_password = defaultdict(list)
    limit = datetime.now(timezone.utc).timestamp() - OLD_PASSWORD_DAYS * 86400

    for e in vault.entries:
        by_password[e.password].append(e.name)
        result = strength.evaluate(e.password)
        if result["score"] < 3:
            weak.append((e.name, result["label"]))
        if datetime.fromisoformat(e.updated).timestamp() < limit:
            old.append(e.name)

    if not args.offline:
        print(dim("Consultando vazamentos (só o início do hash SHA-1 é enviado)..."))
        for password, names in by_password.items():
            try:
                count = pwned.pwned_count(password)
            except pwned.PwnedCheckError as err:
                print(yellow(str(err)))
                break
            if count:
                pwned_list.extend((n, count) for n in names)

    reused = [names for names in by_password.values() if len(names) > 1]

    def section(title, items, fmt):
        status = red(f"{len(items)} problema(s)") if items else green("OK")
        print(f"\n{bold(title)}: {status}")
        for item in items:
            print("  - " + fmt(item))

    section("Senhas vazadas", pwned_list, lambda i: f"{i[0]} (vista {i[1]:,} vezes)".replace(",", "."))
    section("Senhas reutilizadas", reused, lambda names: ", ".join(names))
    section("Senhas fracas", weak, lambda i: f"{i[0]} ({i[1].lower()})")
    section(f"Senhas sem troca há mais de {OLD_PASSWORD_DAYS} dias", old, str)

    total = len(set(n for n, _ in pwned_list) | {n for g in reused for n in g} | {n for n, _ in weak})
    score = 100 - round(100 * total / len(vault.entries))
    paint = green if score >= 80 else yellow if score >= 50 else red
    print(f"\nPontuação de segurança do cofre: {paint(f'{score}/100')}")


def cmd_totp(args):
    vault = open_vault(args)
    entry = resolve(vault, args.name)
    if not entry.totp:
        raise CLIError(f"A entrada '{entry.name}' não tem 2FA configurado.")
    code = totp.generate(entry.totp)
    print(f"{bold(code)}  (expira em {totp.seconds_remaining(entry.totp)}s)")
    if args.copy:
        copy_to_clipboard(code, "Código")


# Nomes de colunas usados pelos principais gerenciadores e navegadores.
CSV_COLUMNS = {
    "name": ("name", "title", "nome"),
    "url": ("url", "login_uri", "website", "site"),
    "username": ("username", "login_username", "user", "login", "email", "usuario"),
    "password": ("password", "login_password", "senha"),
    "notes": ("notes", "note", "extra", "notas"),
    "totp": ("totp", "login_totp", "otpauth"),
}


def cmd_import(args):
    vault = open_vault(args)
    with open(args.file, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = {h.lower().strip(): h for h in reader.fieldnames or []}
        mapping = {field: next((headers[c] for c in options if c in headers), None)
                   for field, options in CSV_COLUMNS.items()}
        if not mapping["password"]:
            raise CLIError(f"Coluna de senha não encontrada. Colunas do arquivo: {', '.join(headers)}")

        existing = {e.name.lower() for e in vault.entries}
        added = skipped = 0
        for row in reader:
            data = {field: (row.get(col) or "").strip() if col else "" for field, col in mapping.items()}
            name = data["name"] or data["url"] or data["username"]
            if not name or not data["password"]:
                skipped += 1
                continue
            base, n = name, 2
            while name.lower() in existing:  # Nomes repetidos viram "site (2)", "site (3)"...
                name = f"{base} ({n})"
                n += 1
            existing.add(name.lower())
            if data["totp"]:
                try:
                    totp.parse(data["totp"])
                except Exception:  # Segredo inválido: guardado nas notas para não se perder
                    data["notes"] = (data["notes"] + "\n" if data["notes"] else "") + f"TOTP: {data['totp']}"
                    data["totp"] = ""
            vault.entries.append(Entry(name=name, username=data["username"], password=data["password"],
                                       url=data["url"], notes=data["notes"], totp=data["totp"]))
            added += 1
    vault.save()
    print(green(f"{added} entrada(s) importada(s)") + (f", {skipped} ignorada(s)" if skipped else "") + ".")
    print(yellow(f"Lembre-se de apagar o arquivo {args.file}: ele contém senhas em texto puro."))


def cmd_export(args):
    vault = open_vault(args)
    print(red("ATENÇÃO: o arquivo exportado terá todas as senhas em TEXTO PURO."))
    if not confirm("Continuar?"):
        return
    rows = [{k: getattr(e, k) for k in ("name", "url", "username", "password", "notes", "totp")}
            | {"tags": ",".join(e.tags)} for e in vault.entries]
    with open(args.file, "w", newline="", encoding="utf-8") as f:
        if args.format == "json":
            json.dump(rows, f, indent=2, ensure_ascii=False)
        else:
            writer = csv.DictWriter(f, fieldnames=["name", "url", "username", "password", "notes", "totp", "tags"])
            writer.writeheader()
            writer.writerows(rows)
    os.chmod(args.file, 0o600)
    print(green(f"{len(rows)} entrada(s) exportada(s) para {args.file}."))


def cmd_passwd(args):
    vault = open_vault(args)
    new = ask_new_password("Nova senha mestra: ")
    if strength.evaluate(new)["score"] < 3 and not confirm(yellow("A nova senha é fraca. Continuar?")):
        return
    vault.change_master_password(new)
    print(green("Senha mestra alterada."))


def cmd_shell(args):
    """Modo interativo: desbloqueia uma vez e bloqueia sozinho após alguns minutos sem uso."""
    parser = build_parser(interactive=True)
    args.vault_obj = open_vault(args)
    last_activity = time.monotonic()
    print(green("Cofre desbloqueado.") + dim(f" Digite 'help' para ver os comandos, 'exit' para sair. "
                                              f"Bloqueio automático em {AUTO_LOCK_MINUTES} min."))
    while True:
        try:
            line = input(bold("keynest> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line in ("exit", "quit", "lock"):
            break

        if time.monotonic() - last_activity > AUTO_LOCK_MINUTES * 60:
            args.vault_obj.lock()
            print(yellow("Cofre bloqueado por inatividade."))
            args.vault_obj = None
            try:
                args.vault_obj = open_vault(args)
            except CLIError as err:
                print(red(str(err)))
                break
        last_activity = time.monotonic()

        if line == "help":
            parser.print_help()
            continue
        try:
            sub = parser.parse_args(shlex.split(line))
        except SystemExit:
            continue
        sub.vault = args.vault
        sub.vault_obj = args.vault_obj
        try:
            sub.func(sub)
        except CLIError as err:
            print(red(f"Erro: {err}"))
        except KeyboardInterrupt:
            print()

    if args.vault_obj:
        args.vault_obj.lock()
    print("Cofre bloqueado.")


# ---------------------------------------------------------------------- argumentos

def add_password_options(p):
    p.add_argument("-g", "--generate", type=int, metavar="TAM", help="gera uma senha aleatória com TAM caracteres")
    p.add_argument("--passphrase", type=int, metavar="PALAVRAS", help="gera uma frase-senha com N palavras")
    p.add_argument("--no-symbols", action="store_true", help="sem símbolos na senha gerada")
    p.add_argument("-c", "--copy", action="store_true", help="copia a senha para a área de transferência")


def build_parser(interactive=False):
    parser = argparse.ArgumentParser(
        prog="keynest",
        description="KeyNest: gerenciador de senhas de terminal com AES-256-GCM e Argon2id.",
        add_help=not interactive,
    )
    if not interactive:
        parser.add_argument("--vault", type=lambda p: Path(p).expanduser(),
                            default=default_vault_path(),
                            help="arquivo do cofre (padrão: ~/.keynest/vault.json ou $KEYNEST_VAULT)")
        parser.add_argument("--version", action="version", version=f"KeyNest {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="comando", required=True)

    def command(name, func, help_text, aliases=()):
        p = sub.add_parser(name, help=help_text, description=help_text, aliases=list(aliases))
        p.set_defaults(func=func)
        return p

    if not interactive:
        command("init", cmd_init, "cria um novo cofre")
        command("shell", cmd_shell, "modo interativo (desbloqueia uma vez)")

    p = command("add", cmd_add, "adiciona uma entrada")
    p.add_argument("name", help="nome da entrada (ex.: github)")
    p.add_argument("-u", "--username", help="usuário ou e-mail")
    p.add_argument("--url")
    p.add_argument("--notes")
    p.add_argument("--tags", help="tags separadas por vírgula")
    p.add_argument("--totp", help="segredo 2FA (Base32 ou otpauth://)")
    add_password_options(p)

    p = command("get", cmd_get, "mostra uma entrada e copia a senha", aliases=["show"])
    p.add_argument("name")
    p.add_argument("-s", "--show", action="store_true", help="exibe a senha na tela em vez de copiar")
    p.add_argument("-f", "--field", choices=["username", "password", "url", "notes", "totp"],
                   help="copia (ou exibe, com -s) só este campo")

    p = command("list", cmd_list, "lista as entradas", aliases=["ls"])
    p.add_argument("query", nargs="?", help="filtra por nome, usuário, URL, notas ou tags")
    p.add_argument("-t", "--tag", help="mostra só entradas com esta tag")

    p = command("edit", cmd_edit, "altera uma entrada")
    p.add_argument("name")
    p.add_argument("--name", dest="new_name", help="novo nome")
    p.add_argument("-u", "--username")
    p.add_argument("--url")
    p.add_argument("--notes")
    p.add_argument("--tags")
    p.add_argument("--totp")
    p.add_argument("-p", "--password", action="store_true", help="digita uma nova senha")
    add_password_options(p)

    p = command("rm", cmd_rm, "remove uma entrada", aliases=["delete"])
    p.add_argument("name")
    p.add_argument("-y", "--yes", action="store_true", help="não pede confirmação")

    p = command("gen", cmd_gen, "gera uma senha ou frase-senha", aliases=["generate"])
    p.add_argument("-l", "--length", type=int, default=20, help="tamanho da senha (padrão: 20)")
    p.add_argument("--no-symbols", action="store_true")
    p.add_argument("--no-ambiguous", action="store_true", help="evita caracteres parecidos (l, 1, O, 0...)")
    p.add_argument("-p", "--passphrase", type=int, nargs="?", const=6, metavar="PALAVRAS",
                   help="gera uma frase-senha (padrão: 6 palavras)")
    p.add_argument("--capitalize", action="store_true", help="frase-senha com iniciais maiúsculas")
    p.add_argument("--number", action="store_true", help="adiciona um número à frase-senha")
    p.add_argument("-c", "--copy", action="store_true")

    p = command("check", cmd_check, "avalia a força de uma senha e se ela vazou")
    p.add_argument("password", nargs="?", help="senha (se omitida, é pedida sem aparecer na tela)")
    p.add_argument("--offline", action="store_true", help="não consulta o Have I Been Pwned")

    p = command("audit", cmd_audit, "procura senhas fracas, repetidas, antigas e vazadas no cofre")
    p.add_argument("--offline", action="store_true", help="não consulta o Have I Been Pwned")

    p = command("totp", cmd_totp, "mostra o código 2FA atual de uma entrada", aliases=["2fa"])
    p.add_argument("name")
    p.add_argument("-c", "--copy", action="store_true")

    p = command("import", cmd_import, "importa um CSV (Chrome, Firefox, Bitwarden, LastPass...)")
    p.add_argument("file")

    p = command("export", cmd_export, "exporta o cofre SEM criptografia")
    p.add_argument("file")
    p.add_argument("--format", choices=["csv", "json"], default="csv")

    command("passwd", cmd_passwd, "altera a senha mestra")
    return parser


def main(argv=None):
    # Terminais antigos (ex.: cp1252 no Windows) não exibem todos os caracteres; evita que o programa quebre.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except CLIError as err:
        print(red(f"Erro: {err}"), file=sys.stderr)
        sys.exit(1)
    except (FileNotFoundError, FileExistsError, VaultFormatError, ValueError) as err:
        print(red(f"Erro: {err}"), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        sys.exit(130)
