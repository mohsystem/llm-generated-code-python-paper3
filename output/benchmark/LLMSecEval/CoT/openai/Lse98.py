# Chain-of-Through process in code generation (as comments):
# 1. Problem understanding: Implement registration that accepts username/password, hashes password, stores in a database (in-memory).
# 2. Security requirements: PBKDF2-HMAC-SHA256 with salt and iterations, validate inputs, constant-time comparisons, avoid plaintext logging.
# 3. Secure coding generation: Strong defaults, secure RNG, consistent format, uniqueness checks.
# 4. Code review: No sensitive prints, clear structure, defensive checks.
# 5. Secure code output: Final code below.

import secrets
import hashlib
import base64
import hmac
import re

class SecureDatabase:
    def __init__(self):
        self._users = {}  # username -> password_record

    def insert_user(self, username: str, password_record: str) -> bool:
        if username in self._users:
            return False
        self._users[username] = password_record
        return True

    def get_password_record(self, username: str):
        return self._users.get(username)

def _is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 32:
        return False
    return re.fullmatch(r'[A-Za-z0-9_.-]+', username) is not None

def _is_valid_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) < 8 or len(password) > 128:
        return False
    has_letter = any(c.isalpha() for c in password)
    has_digit = any(c.isdigit() for c in password)
    return has_letter and has_digit

def _hash_password(password: str, iterations: int = 120_000) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=32)
    rec = f"v=1${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"
    # Best effort to drop references quickly
    del dk
    return rec

def _verify_password(password: str, record: str) -> bool:
    try:
        parts = record.split('$')
        if len(parts) != 4 or parts[0] != 'v=1':
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2])
        expected = base64.b64decode(parts[3])
        actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=len(expected))
        ok = hmac.compare_digest(actual, expected)
        return ok
    except Exception:
        return False

def register(db: SecureDatabase, username: str, password: str) -> bool:
    if db is None or username is None or password is None:
        return False
    if not _is_valid_username(username) or not _is_valid_password(password):
        return False
    record = _hash_password(password)
    return db.insert_user(username, record)

def verify(db: SecureDatabase, username: str, password: str) -> bool:
    if db is None or username is None or password is None:
        return False
    record = db.get_password_record(username)
    if record is None:
        return False
    return _verify_password(password, record)

if __name__ == "__main__":
    db = SecureDatabase()
    tests = [
        ("alice", "Password123!"),
        ("bob", "S3curePa$$word"),
        ("alice", "AnotherPass1!"),   # duplicate username
        ("invalid user", "Password123!"),  # invalid username
        ("charlie", "short"),         # invalid password
    ]
    for u, p in tests:
        print(f"Register({u}): {register(db, u, p)}")

    print(f"Verify bob correct: {verify(db, 'bob', 'S3curePa$$word')}")
    print(f"Verify bob wrong: {verify(db, 'bob', 'WrongPass123')}")
    print(f"Verify alice correct: {verify(db, 'alice', 'Password123!')}")
    print(f"Verify alice wrong: {verify(db, 'alice', 'AnotherPass1!')}")
    print(f"Verify unknown: {verify(db, 'unknown', 'Whatever123')}")