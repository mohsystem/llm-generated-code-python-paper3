import os
import re
import hmac
import secrets
import hashlib
from typing import Dict, Tuple

class SecureAuthDB:
    def __init__(self) -> None:
        self._db: Dict[str, Tuple[bytes, bytes, int]] = {}  # username -> (salt, hash, iterations)
        self._username_re = re.compile(r"^[A-Za-z0-9_]{3,32}$")
        self._iterations = 210_000
        self._salt_len = 16
        self._dk_len = 32

    def _validate_username(self, username: str) -> bool:
        if not isinstance(username, str):
            return False
        if len(username) < 3 or len(username) > 32:
            return False
        return bool(self._username_re.match(username))

    def _password_policy(self, password: str) -> bool:
        if not isinstance(password, str):
            return False
        if len(password) < 10 or len(password) > 128:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        return has_upper and has_lower and has_digit and has_special

    def register_user(self, username: str, password: str) -> bool:
        if not self._validate_username(username):
            return False
        if not self._password_policy(password):
            return False
        if username in self._db:
            return False
        salt = secrets.token_bytes(self._salt_len)
        pwd_bytes = password.encode("utf-8")
        dk = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, self._iterations, dklen=self._dk_len)
        # Do not store password, only hash
        self._db[username] = (salt, dk, self._iterations)
        return True

    def authenticate(self, username: str, password: str) -> bool:
        if not self._validate_username(username):
            return False
        rec = self._db.get(username)
        if not rec:
            return False
        salt, stored, iterations = rec
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=len(stored))
        return hmac.compare_digest(stored, dk)

    def login(self, username: str, password: str) -> str:
        ok = self.authenticate(username, password)
        return "Redirect: /dashboard" if ok else "Redirect: /login"


def main() -> None:
    db = SecureAuthDB()
    print("Register alice:", db.register_user("alice", "Str0ng!Pass1"))
    print("Register bob:", db.register_user("bob", "B0b$Secure#2024"))
    print("Register charlie:", db.register_user("charlie", "Ch@rlie2025!!"))

    tests = [
        ("alice", "Str0ng!Pass1"),    # success
        ("alice", "wrongpassword!"),  # wrong password
        ("unknown", "AnyPassw0rd!"),  # unknown user
        ("bad user", "Xx1!invalid"),  # invalid username
        ("bob", "B0b$Secure#2024"),   # success
    ]

    for i, (u, p) in enumerate(tests, 1):
        result = db.login(u, p)
        print(f"Test {i} login({u}, [redacted]): {result}")

if __name__ == "__main__":
    main()