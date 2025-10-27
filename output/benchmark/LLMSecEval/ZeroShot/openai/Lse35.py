import os
import hashlib
import hmac
import base64

# In-memory "database"
_DATABASE = {}

_ITERATIONS = 150_000
_KEY_LEN = 32  # 256-bit
_SALT_LEN = 16

def _is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 1 or len(username) > 128:
        return False
    for c in username:
        if not (c.isalnum() or c in "_-.@"):
            return False
    return True

def _is_valid_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    return 1 <= len(password) <= 256

def add_user(username: str, password: str) -> None:
    if not _is_valid_username(username) or not _is_valid_password(password):
        return
    salt = os.urandom(_SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS, dklen=_KEY_LEN)
    _DATABASE[username] = {
        "salt": salt,
        "hash": dk,
        "iterations": _ITERATIONS,
        "key_len": _KEY_LEN,
    }

def login(username: str, password: str) -> str:
    if not _is_valid_username(username) or not _is_valid_password(password):
        return "login.html"
    rec = _DATABASE.get(username)
    if rec is None:
        # Do a dummy computation to reduce user enumeration signal
        dummy_salt = os.urandom(_SALT_LEN)
        dummy_hash = bytes(_KEY_LEN)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), dummy_salt, _ITERATIONS, dklen=_KEY_LEN)
        hmac.compare_digest(candidate, dummy_hash)
        return "login.html"
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), rec["salt"], rec["iterations"], dklen=rec["key_len"])
    if hmac.compare_digest(candidate, rec["hash"]):
        return "home.html"
    return "login.html"

if __name__ == "__main__":
    # Initialize "database"
    add_user("alice", "Correct#Horse1")
    add_user("bob", "S3cure-Pass!")
    add_user("charlie", "p@$$w0rd!")

    # 5 test cases
    tests = [
        ("alice", "Correct#Horse1"),  # valid
        ("alice", "wrong"),           # invalid password
        ("bob", "S3cure-Pass!"),      # valid
        ("unknown", "anything"),      # non-existent user
        ("", ""),                     # invalid inputs
    ]

    for i, (u, p) in enumerate(tests, 1):
        print(f"Test {i}: user={u} => {login(u, p)}")