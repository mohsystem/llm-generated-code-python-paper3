import base64
import hashlib
import secrets
from typing import Optional

ITERATIONS = 210_000
SALT_LEN = 16
DK_LEN = 32
MIN_USERNAME_LEN = 3
MAX_USERNAME_LEN = 32
MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 128

_ALLOWED_USER_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
_SPECIALS = set("!@#$%^&*()_+-=[]{};':\"\\|,.<>/?")

def _is_valid_username(username: Optional[str]) -> bool:
    if username is None:
        return False
    if not (MIN_USERNAME_LEN <= len(username) <= MAX_USERNAME_LEN):
        return False
    return all(c in _ALLOWED_USER_CHARS for c in username)

def _is_valid_password(password: Optional[str]) -> bool:
    if password is None:
        return False
    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        return False
    has_u = any('A' <= c <= 'Z' for c in password)
    has_l = any('a' <= c <= 'z' for c in password)
    has_d = any('0' <= c <= '9' for c in password)
    has_s = any(c in _SPECIALS for c in password)
    return has_u and has_l and has_d and has_s

def register_user(username: str, password: str) -> str:
    if not _is_valid_username(username):
        raise ValueError("Invalid input.")
    if not _is_valid_password(password):
        raise ValueError("Invalid input.")

    salt = secrets.token_bytes(SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=DK_LEN)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(dk).decode("ascii")
    return f"pbkdf2_sha256${ITERATIONS}${salt_b64}${hash_b64}"

if __name__ == "__main__":
    tests = [
        ("alice_01", "S3cure!Passw0rd"),
        ("bob-user", "An0ther$Strong1"),
        ("charlie.test", "Ultr@S3curePass!"),
        ("dora-2025", "G00d#Password_++"),
        ("eve.user", "Y3t@N0ther_Strong"),
    ]
    for u, p in tests:
        try:
            rec = register_user(u, p)
            print(f"Registered: {u} -> {rec}")
        except Exception:
            print(f"Registration failed for {u}")