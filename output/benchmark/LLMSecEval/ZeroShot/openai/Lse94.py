import os
import base64
import hashlib
import secrets
from dataclasses import dataclass

@dataclass
class UserRecord:
    username: str
    salt_b64: str
    hash_b64: str

class InMemoryDatabase:
    def __init__(self):
        self._store = {}

    def insert(self, record: UserRecord) -> bool:
        if not record or not record.username:
            return False
        if record.username in self._store:
            return False
        self._store[record.username] = record
        return True

    def get(self, username: str):
        return self._store.get(username)

def generate_salt(n: int = 16) -> bytes:
    if n <= 0:
        raise ValueError("Salt length must be positive")
    return secrets.token_bytes(n)

def hash_password(password: str, salt: bytes, iterations: int = 100_000, dklen: int = 32) -> str:
    if not password:
        raise ValueError("Empty password")
    if not salt:
        raise ValueError("Empty salt")
    if iterations < 10000:
        raise ValueError("Iterations too low")
    if dklen < 16:
        raise ValueError("dklen too small")
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=dklen)
    return base64.b64encode(dk).decode('ascii')

def register_user(username: str, password: str, db: InMemoryDatabase) -> bool:
    if db is None:
        raise ValueError("db is None")
    if not username or username.strip() == "":
        return False
    if not password:
        return False
    salt = generate_salt(16)
    hash_b64 = hash_password(password, salt, 100_000, 32)
    record = UserRecord(username=username, salt_b64=base64.b64encode(salt).decode('ascii'), hash_b64=hash_b64)
    return db.insert(record)

if __name__ == "__main__":
    db = InMemoryDatabase()
    test_users = [
        ("alice", "S3cure!Pass1"),
        ("bob", "An0ther$Pass2"),
        ("charlie", "Str0ng#Key3"),
        ("diana", "My$Passw0rd4"),
        ("eve", "Ultr@Safe5"),
    ]
    for u, p in test_users:
        ok = register_user(u, p, db)
        print(f"Insert user {u}: {'OK' if ok else 'FAIL'}")

    for u, _ in test_users:
        rec = db.get(u)
        if rec:
            print(f"{u} -> salt={rec.salt_b64}, hash={rec.hash_b64}")