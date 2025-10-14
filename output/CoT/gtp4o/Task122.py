import os
import base64
import hashlib
import hmac
import secrets
import re

class SecureUserStore:
    def __init__(self):
        self.users = {}
        self.iterations = 200_000
        self.salt_len = 16
        self.key_len = 32

    def signup(self, username: str, password: str) -> bool:
        if not self._validate_username(username) or not self._validate_password(password):
            return False
        if username in self.users:
            return False
        salt = os.urandom(self.salt_len)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self.iterations, dklen=self.key_len)
        record = f"v1${self.iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"
        self.users[username] = record
        return True

    def verify(self, username: str, password: str) -> bool:
        record = self.users.get(username)
        if not record:
            return False
        try:
            parts = record.split('$')
            if len(parts) != 4 or parts[0] != 'v1':
                return False
            iterations = int(parts[1])
            salt = base64.b64decode(parts[2])
            expected = base64.b64decode(parts[3])
            actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=len(expected))
            return secrets.compare_digest(expected, actual)
        except Exception:
            return False

    def get_record(self, username: str) -> str | None:
        return self.users.get(username)

    def _validate_username(self, username: str) -> bool:
        if username is None or len(username) < 3 or len(username) > 32:
            return False
        return re.fullmatch(r'[A-Za-z0-9._-]+', username) is not None

    def _validate_password(self, password: str) -> bool:
        if password is None or len(password) < 10:
            return False
        if any(c.isspace() for c in password):
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() and not c.isspace() for c in password)
        return has_upper and has_lower and has_digit and has_special

def main():
    store = SecureUserStore()
    print("Test1 (valid signup):", store.signup("alice", "Str0ngPass!"))
    print("Test2 (duplicate username):", store.signup("alice", "An0ther#Pass"))
    print("Test3 (invalid username):", store.signup("bob space", "Str0ngPass!"))
    print("Test4 (weak password):", store.signup("carol", "weak"))
    print("Test5 (another valid signup):", store.signup("charlie", "G00d#Password"))
    print("Verify alice:", store.verify("alice", "Str0ngPass!"))
    print("Verify alice wrong:", store.verify("alice", "WrongPass!"))

if __name__ == "__main__":
    main()