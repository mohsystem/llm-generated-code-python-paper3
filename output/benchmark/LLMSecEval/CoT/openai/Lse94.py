import os
import hmac
import hashlib
import base64
from typing import Dict, Tuple, Optional

SALT_LEN = 16
HASH_LEN = 32
ITERATIONS = 100_000

class UserRecord:
    def __init__(self, username: str, salt: bytes, hash_bytes: bytes):
        self.username = username
        self.salt = salt
        self.hash = hash_bytes

class InMemoryDB:
    def __init__(self):
        self._store: Dict[str, UserRecord] = {}

    def insert(self, rec: UserRecord) -> bool:
        if rec.username in self._store:
            return False
        self._store[rec.username] = rec
        return True

    def get(self, username: str) -> Optional[UserRecord]:
        return self._store.get(username)

    def size(self) -> int:
        return len(self._store)

def is_valid_username(username: str) -> bool:
    if username is None or len(username) < 3 or len(username) > 32:
        return False
    return username.isidentifier() or username.replace('_', '').isalnum()

def is_valid_password(password: str) -> bool:
    return password is not None and len(password) >= 8

def generate_salt() -> bytes:
    return os.urandom(SALT_LEN)

def hash_password(password: str, salt: bytes, iterations: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=dklen)

def create_user_record(username: str, password: str) -> UserRecord:
    salt = generate_salt()
    h = hash_password(password, salt, ITERATIONS, HASH_LEN)
    return UserRecord(username, salt, h)

def register_user(db: InMemoryDB, username: str, password: str) -> bool:
    if not is_valid_username(username) or not is_valid_password(password):
        return False
    rec = create_user_record(username, password)
    return db.insert(rec)

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

if __name__ == "__main__":
    db = InMemoryDB()
    tests = [
        ("alice_01", "S3cur3P@ssw0rd!"),
        ("bob_user", "Another$trong1"),
        ("charlie_3", "passw0rdLongEnough"),
        ("bob_user", "Another$trong1"), # duplicate
        ("eve_user", "Y3t@An0th3rP@ss"),
    ]
    for u, p in tests:
        ok = register_user(db, u, p)
        print(f"Register '{u}': {ok}")
        rec = db.get(u)
        if rec:
            print(f"  salt(b64)={b64(rec.salt)}")
            print(f"  hash(b64)={b64(rec.hash)}")
    print(f"Total users stored: {db.size()}")