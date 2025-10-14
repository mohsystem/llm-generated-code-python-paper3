# Chain-of-Through Step 1-5 integrated via secure functions and comments.

import os
import time
import base64
import secrets
import hashlib
import hmac

# In-memory storage
_USERS = {}  # email -> dict(salt, hash, iterations, token_hash, token_expiry)

_SALT_LEN = 16
_ITERATIONS = 100_000
_KEY_LEN = 32
_TOKEN_TTL = 600  # seconds


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _pbkdf2(password: str, salt: bytes, iterations: int, dk_len: int) -> bytes:
    # PBKDF2-HMAC-SHA256
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dk_len)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def is_password_strong(p: str) -> bool:
    if p is None:
        return False
    if len(p) < 10 or len(p) > 100:
        return False
    up = any(c.isupper() for c in p)
    lo = any(c.islower() for c in p)
    di = any(c.isdigit() for c in p)
    sp = any(not c.isalnum() for c in p)
    if not (up and lo and di and sp):
        return False
    lower = p.lower()
    for bad in ("password", "12345", "qwerty", "letmein", "admin"):
        if bad in lower:
            return False
    return True


def create_user(email: str, password: str) -> bool:
    if not email or not password:
        return False
    if email in _USERS:
        return False
    if not is_password_strong(password):
        return False
    salt = os.urandom(_SALT_LEN)
    ph = _pbkdf2(password, salt, _ITERATIONS, _KEY_LEN)
    _USERS[email] = {
        "salt": salt,
        "hash": ph,
        "iterations": _ITERATIONS,
        "token_hash": None,
        "token_expiry": 0.0,
    }
    return True


def request_reset(email: str):
    user = _USERS.get(email)
    if not user:
        return None
    token_bytes = secrets.token_bytes(32)
    token = _base64url(token_bytes)
    tok_hash = _sha256(token.encode("utf-8"))
    user["token_hash"] = tok_hash
    user["token_expiry"] = time.time() + _TOKEN_TTL
    return token


def reset_password(token: str, new_password: str) -> bool:
    if token is None or new_password is None:
        return False
    tok_hash = _sha256(token.encode("utf-8"))
    now = time.time()
    matched_email = None
    for email, u in _USERS.items():
        th = u.get("token_hash")
        if th is not None and _ct_eq(th, tok_hash):
            matched_email = email
            break
    if matched_email is None:
        return False
    u = _USERS[matched_email]
    if u["token_expiry"] < now:
        u["token_hash"] = None
        u["token_expiry"] = 0.0
        return False
    if not is_password_strong(new_password):
        return False
    salt = os.urandom(_SALT_LEN)
    ph = _pbkdf2(new_password, salt, _ITERATIONS, _KEY_LEN)
    u["salt"] = salt
    u["hash"] = ph
    u["iterations"] = _ITERATIONS
    u["token_hash"] = None
    u["token_expiry"] = 0.0
    return True


def main():
    print("Python tests:")
    # 1) Unknown user request
    t1 = request_reset("unknown@example.com")
    print("Test1 token for unknown user should be None:", t1)

    # 2) Create user and request reset; wrong token
    created = create_user("alice@example.com", "OldPassw0rd!")
    print("Test2 created user:", created)
    token = request_reset("alice@example.com")
    print("Test2 got token:", token is not None)
    wrong = reset_password("badtoken", "NewPassw0rd!")
    print("Test2 reset with wrong token:", wrong)

    # 3) Weak password
    weak = reset_password(token, "weak")
    print("Test3 reset with weak password:", weak)

    # 4) Successful reset
    ok = reset_password(token, "N3w_Str0ngPass!")
    print("Test4 reset with correct token and strong password:", ok)

    # 5) Reuse token; then new token and reset
    reuse = reset_password(token, "AnotherStr0ng!")
    print("Test5 reuse token:", reuse)
    token2 = request_reset("alice@example.com")
    ok2 = reset_password(token2, "UltraStr0ng#2025")
    print("Test5 new token reset:", ok2)


if __name__ == "__main__":
    main()