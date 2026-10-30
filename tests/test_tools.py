import hashlib
import io
import string

import pytest

from keynest import generator, pwned, strength, totp


def test_password_has_every_selected_class():
    for _ in range(50):
        pw = generator.generate_password(12)
        assert len(pw) == 12
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in generator.SYMBOLS for c in pw)


def test_password_options():
    assert not any(c in generator.SYMBOLS for c in generator.generate_password(40, symbols=False))
    assert not set(generator.generate_password(200, exclude_ambiguous=True)) & generator.AMBIGUOUS
    with pytest.raises(ValueError):
        generator.generate_password(2)


def test_passphrase():
    words = generator.generate_passphrase(6).split("-")
    assert len(words) == 6
    assert all(w in generator.wordlist() for w in words)
    assert len(generator.wordlist()) == 7776


def test_strength():
    assert strength.evaluate("123456")["score"] == 0
    assert strength.evaluate("Senha123!")["score"] <= 1
    assert strength.evaluate("P@ssw0rd")["score"] <= 1
    assert strength.evaluate(generator.generate_password(20))["score"] == 4
    assert strength.evaluate("correct-horse-battery-staple-orbit")["score"] >= 3


def test_totp_rfc6238_vectors():
    # Vetores oficiais da RFC 6238 (segredo "12345678901234567890", 8 dígitos, SHA-1)
    uri = "otpauth://totp/Teste?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8"
    assert totp.generate(uri, at=59) == "94287082"
    assert totp.generate(uri, at=1111111109) == "07081804"
    assert totp.generate(uri, at=2000000000) == "69279037"


def test_totp_secret_formats():
    assert totp.parse("gezd gnbv gy3t qojq") == ("GEZDGNBVGY3TQOJQ", 6, 30, "SHA1")
    assert len(totp.generate("JBSWY3DPEHPK3PXP")) == 6
    with pytest.raises(Exception):
        totp.parse("isso não é base32!")


def test_pwned_uses_only_hash_prefix(monkeypatch):
    digest = hashlib.sha1(b"password").hexdigest().upper()
    requested = {}

    def fake_urlopen(request, timeout):
        requested["url"] = request.full_url
        body = f"0000000000000000000000000000000000A:0\n{digest[5:]}:9545824\n"
        return io.BytesIO(body.encode())

    monkeypatch.setattr(pwned.urllib.request, "urlopen", fake_urlopen)
    assert pwned.pwned_count("password") == 9545824
    assert requested["url"] == "https://api.pwnedpasswords.com/range/" + digest[:5]
