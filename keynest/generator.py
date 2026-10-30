"""Geração de senhas e frases-senha com o gerador criptograficamente seguro do sistema (módulo secrets)."""
import math
import secrets
import string
from functools import lru_cache
from importlib.resources import files

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("Il1O0o|")


@lru_cache(maxsize=1)
def wordlist():
    """Lista de palavras da EFF (7776 palavras, ~12,9 bits de entropia por palavra)."""
    return files("keynest").joinpath("wordlist.txt").read_text(encoding="utf-8").split()


def generate_password(length=20, lower=True, upper=True, digits=True, symbols=True, exclude_ambiguous=False):
    classes = [chars for chars, enabled in ((LOWER, lower), (UPPER, upper), (DIGITS, digits), (SYMBOLS, symbols))
               if enabled]
    if not classes:
        raise ValueError("Selecione pelo menos um tipo de caractere.")
    if exclude_ambiguous:
        classes = ["".join(c for c in chars if c not in AMBIGUOUS) for chars in classes]
    if length < len(classes):
        raise ValueError(f"O tamanho mínimo com essas opções é {len(classes)}.")

    # Garante pelo menos um caractere de cada tipo escolhido e embaralha o resultado.
    pool = "".join(classes)
    chars = [secrets.choice(c) for c in classes]
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words=6, separator="-", capitalize=False, add_number=False):
    if words < 1:
        raise ValueError("A frase precisa de pelo menos uma palavra.")
    chosen = [secrets.choice(wordlist()) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    if add_number:
        i = secrets.randbelow(len(chosen))
        chosen[i] += str(secrets.randbelow(10))
    return separator.join(chosen)


def password_entropy(length, lower=True, upper=True, digits=True, symbols=True):
    pool = sum(len(c) for c, on in ((LOWER, lower), (UPPER, upper), (DIGITS, digits), (SYMBOLS, symbols)) if on)
    return length * math.log2(pool)


def passphrase_entropy(words):
    return words * math.log2(len(wordlist()))
