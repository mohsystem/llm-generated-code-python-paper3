import os
import hmac
import hashlib
import secrets

class Task42:
    def __init__(self, iterations: int = 100_000, salt_len: int = 16, dk_len: int = 32):
        self._store = {}
        self._iterations = iterations
        self._salt_len = salt_len
        self._dk_len = dk_len

    def _is_valid_username(self, username: str) -> bool:
        if not isinstance(username, str):
            return False
        if len(username) < 3 or len(username) > 50:
            return False
        for c in username:
            if not (c.isalnum() or c in "_.-"):
                return False
        return True

    def _is_valid_password(self, password: str) -> bool:
        if not isinstance(password, str) or len(password) < 8:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        return has_upper and has_lower and has_digit and has_symbol

    def register_user(self, username: str, password: str) -> bool:
        if not self._is_valid_username(username) or not self._is_valid_password(password):
            return False
        if username in self._store:
            return False
        salt = os.urandom(self._salt_len)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self._iterations, dklen=self._dk_len)
        self._store[username] = (salt, dk, self._iterations)
        return True

    def authenticate(self, username: str, password: str) -> bool:
        rec = self._store.get(username)
        if not rec:
            return False
        salt, dk_stored, iters = rec
        dk_candidate = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters, dklen=len(dk_stored))
        return secrets.compare_digest(dk_candidate, dk_stored)


if __name__ == "__main__":
    auth = Task42()
    print("Test1 register alice:", auth.register_user("alice", "S3cure!Passw0rd"))
    print("Test2 auth alice correct:", auth.authenticate("alice", "S3cure!Passw0rd"))
    print("Test3 auth alice wrong:", auth.authenticate("alice", "WrongPass!1"))
    print("Test4 duplicate register alice:", auth.register_user("alice", "An0ther!Pass"))
    print("Test5 bob short register (expect False):", auth.register_user("bob", "short1!"))
    print("Test5b bob good register:", auth.register_user("bob", "G00d!Passw0rd"))
    print("Test5c auth bob correct:", auth.authenticate("bob", "G00d!Passw0rd"))