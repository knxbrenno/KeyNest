"""Avaliação da força de senhas: entropia estimada com penalidades para padrões previsíveis."""
import math
import re

# Algumas das senhas mais usadas no mundo (inclui variações comuns no Brasil).
COMMON = {
    "123456", "123456789", "12345678", "password", "qwerty", "12345", "1234567", "111111", "123123", "abc123",
    "1234567890", "senha", "senha123", "password1", "admin", "admin123", "iloveyou", "000000", "qwerty123",
    "1q2w3e4r", "654321", "666666", "123321", "121212", "dragon", "monkey", "letmein", "football", "brasil",
    "flamengo", "corinthians", "palmeiras", "123mudar", "mudar123", "princesa", "minhasenha", "welcome",
    "master", "sunshine", "shadow", "superman", "batman", "trustno1", "root", "toor", "changeme", "teste",
    "teste123", "q1w2e3r4", "1qaz2wsx", "zaq12wsx", "asdfgh", "asdf1234", "passw0rd", "p@ssw0rd", "senha1",
}

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
LEET = str.maketrans("@4310$5!7", "aaeiossit")

LABELS = ["Muito fraca", "Fraca", "Razoável", "Forte", "Muito forte"]


def _charset_size(password):
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33
    return size or 1


def _has_sequence(password, size=4):
    lower = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - size + 1):
            chunk = seq[i:i + size]
            if chunk in lower or chunk[::-1] in lower:
                return True
    return False


def evaluate(password):
    """Retorna score (0-4), rótulo, entropia estimada em bits e a lista de problemas encontrados."""
    warnings = []
    entropy = len(password) * math.log2(_charset_size(password))

    lower = password.lower()
    stripped = re.sub(r"[\d!@#$%*.]+$", "", lower)  # "Senha123!" -> "senha"
    candidates = {lower, stripped, lower.translate(LEET), stripped.translate(LEET)}  # "P@ssw0rd" -> "password"
    if candidates & COMMON:
        warnings.append("É uma das senhas mais usadas do mundo.")
        entropy = min(entropy, 10)

    if len(password) < 8:
        warnings.append("Muito curta: use pelo menos 12 caracteres.")
    elif len(password) < 12:
        warnings.append("Curta: o ideal é 12 caracteres ou mais.")

    if re.search(r"(.)\1{2,}", password):
        warnings.append("Tem caracteres repetidos em sequência (ex.: aaa).")
        entropy *= 0.8
    if _has_sequence(password):
        warnings.append("Tem sequências previsíveis (ex.: 1234, abcd, qwerty).")
        entropy *= 0.75
    if re.search(r"(19|20)\d{2}", password):
        warnings.append("Contém um ano, que costuma ser fácil de adivinhar.")
        entropy *= 0.9
    if password.isdigit():
        warnings.append("Contém apenas números.")
    if password.isalpha() and len(password) < 16:
        warnings.append("Contém apenas letras.")

    thresholds = (28, 40, 60, 80)
    score = sum(entropy >= t for t in thresholds)
    return {"score": score, "label": LABELS[score], "entropy": round(entropy, 1), "warnings": warnings}


def crack_time(entropy, guesses_per_second=1e10):
    """Tempo médio para quebrar offline com uma GPU potente (10 bilhões de tentativas/s)."""
    seconds = 2 ** entropy / 2 / guesses_per_second
    for unit, size in (("séculos", 3.15e9), ("anos", 3.15e7), ("dias", 86400), ("horas", 3600), ("minutos", 60)):
        if seconds >= size:
            value = seconds / size
            return f"{value:,.0f} {unit}".replace(",", ".") if value < 1e6 else f"mais de 1 milhão de {unit}"
    return "menos de 1 minuto" if seconds >= 1 else "instantâneo"
