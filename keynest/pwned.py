"""
Verifica se uma senha apareceu em vazamentos usando a API do Have I Been Pwned.

Usa k-anonimato: só os 5 primeiros caracteres do hash SHA-1 são enviados; a senha nunca sai do computador.
"""
import hashlib
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/"


class PwnedCheckError(Exception):
    pass


def pwned_count(password, timeout=10):
    """Quantas vezes a senha aparece em vazamentos conhecidos (0 = nunca vista)."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    request = urllib.request.Request(API_URL + prefix, headers={
        "User-Agent": "KeyNest-password-manager",
        "Add-Padding": "true",  # Respostas com tamanho uniforme dificultam a análise do tráfego
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except OSError as err:
        raise PwnedCheckError(f"Não foi possível consultar o Have I Been Pwned: {err}") from err

    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate == suffix:
            return int(count)
    return 0
