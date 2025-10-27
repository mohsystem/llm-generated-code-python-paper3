import hmac
import hashlib
import secrets
import string
from typing import Dict, Tuple

SALT_LEN = 16
KEY_LEN = 32  # 256-bit
ITERATIONS = 210_000

# username -> (salt, hash, iterations)
STORE: Dict[str, Tuple[bytes, bytes, int]] = {}


def _valid_username(u: str) -> bool:
    if not isinstance(u, str):
        return False
    u = u.strip()
    if len(u) == 0 or len(u) > 64:
        return False
    allowed = set(string.ascii_letters + string.digits + "_.-")
    return all(ch in allowed for ch in u)


def _valid_password_for_login(p: str) -> bool:
    if not isinstance(p, str):
        return False
    return 1 <= len(p) <= 1024


def _is_password_strong(p: str) -> bool:
    if not isinstance(p, str) or len(p) < 12 or len(p) > 1024:
        return False
    has_u = any(c.isupper() for c in p)
    has_l = any(c.islower() for c in p)
    has_d = any(c.isdigit() for c in p)
    has_s = any(c in string.punctuation for c in p)
    return has_u and has_l and has_d and has_s


def _pbkdf2(password: str, salt: bytes, iterations: int, key_len: int) -> bytes:
    # Treat inputs as untrusted
    if not isinstance(password, str) or not isinstance(salt, (bytes, bytearray)):
        raise ValueError("Invalid inputs")
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=key_len)


def register_user(username: str, password: str) -> None:
    if not _valid_username(username):
        raise ValueError("Invalid username")
    if not _is_password_strong(password):
        raise ValueError("Password does not meet policy")
    salt = secrets.token_bytes(SALT_LEN)
    dk = _pbkdf2(password, salt, ITERATIONS, KEY_LEN)
    STORE[username] = (salt, dk, ITERATIONS)


def check_mod(username: str, password: str) -> str:
    if not _valid_username(username) or not _valid_password_for_login(password):
        return "false"
    rec = STORE.get(username)
    if rec is None:
        return "false"
    salt, stored_dk, iters = rec
    try:
        cand = _pbkdf2(password, salt, iters, len(stored_dk))
        ok = hmac.compare_digest(cand, stored_dk)
    except Exception:
        ok = False
    return "true" if ok else "false"


if __name__ == "__main__":
    # Initialize users securely
    register_user("alice", "Str0ng!Pass#1")
    register_user("bob", "Another$Pass2")
    register_user("eve", "Complex%Pass3")

    # 5 test cases
    print(check_mod("alice", "Str0ng!Pass#1"))  # true
    print(check_mod("alice", "wrong"))          # false
    print(check_mod("unknown", "whatever"))     # false
    print(check_mod("", "nope"))                # false
    print(check_mod("bob", "Another$Pass2"))    # true