import os
import hmac
import hashlib
from typing import Optional, Dict, Tuple

HOME_URL = "/home"
ITERATIONS = 100_000
SALT_LEN = 16
DK_LEN = 32

class AuthDB:
    def __init__(self) -> None:
        # username -> (salt, hash, iterations)
        self._db: Dict[str, Tuple[bytes, bytes, int]] = {}

    def _derive_key(self, password: bytes, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=DK_LEN)

    def add_user(self, username: str, password: str) -> None:
        if not username or password is None:
            return
        salt = os.urandom(SALT_LEN)
        pwd_bytes = password.encode("utf-8")
        key = self._derive_key(pwd_bytes, salt, ITERATIONS)
        # Best-effort clear password bytes (strings immutable; bytes object will be GC'ed)
        self._db[username] = (salt, key, ITERATIONS)

    def login(self, username: str, password: str) -> Optional[str]:
        if username not in self._db or password is None:
            return None
        salt, stored_key, iterations = self._db[username]
        pwd_bytes = password.encode("utf-8")
        computed = self._derive_key(pwd_bytes, salt, iterations)
        if hmac.compare_digest(computed, stored_key):
            return HOME_URL
        return None

def main():
    db = AuthDB()
    db.add_user("alice", "Password123!")
    db.add_user("bob", "s3cur3")

    tests = [
        ("alice", "Password123!"), # success
        ("alice", "wrong"),        # wrong password
        ("bob", "s3cur3"),         # success
        ("charlie", "anything"),   # user not found
        ("", ""),                  # invalid username
    ]
    for i, (u, p) in enumerate(tests, 1):
        result = db.login(u, p)
        print(f"Test {i}: {result if result else 'login failed'}")

if __name__ == "__main__":
    main()