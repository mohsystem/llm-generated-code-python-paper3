# Chain-of-Through:
# 1) Understand: in-memory secure registration/login. Store "hex(hash):hex(salt)".
# 2) Security: PBKDF2-HMAC-SHA256, os.urandom salt, constant-time compare, input validation.
# 3) Implement securely.
# 4) Review: no secrets printed, cleanup where possible.
# 5) Output final secure code.

import os
import hmac
import hashlib
import re

class Lse95:
    def __init__(self, iterations: int = 120_000, salt_len: int = 16, key_len: int = 32):
        self._db = {}
        self._iterations = iterations
        self._salt_len = salt_len
        self._key_len = key_len

    def register_user(self, username: str, password: str) -> bool:
        if not self._valid_username(username) or not self._valid_password(password):
            return False
        if username in self._db:
            return False
        salt = os.urandom(self._salt_len)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self._iterations, dklen=self._key_len)
        record = dk.hex() + ":" + salt.hex()
        self._db[username] = record
        return True

    def verify_login(self, username: str, password: str) -> bool:
        record = self._db.get(username)
        if not record:
            return False
        parts = record.split(":")
        if len(parts) != 2:
            return False
        stored_hash = bytes.fromhex(parts[0])
        salt = bytes.fromhex(parts[1])
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self._iterations, dklen=len(stored_hash))
        ok = hmac.compare_digest(stored_hash, dk)
        return ok

    @staticmethod
    def _valid_username(u: str) -> bool:
        if not isinstance(u, str) or len(u) < 3 or len(u) > 64:
            return False
        return re.fullmatch(r"[A-Za-z0-9_.-]+", u) is not None

    @staticmethod
    def _valid_password(p: str) -> bool:
        if not isinstance(p, str) or len(p) < 8 or len(p) > 1024:
            return False
        # Disallow control chars
        return not any(ord(c) < 32 for c in p)

if __name__ == "__main__":
    store = Lse95()

    # Test case 1: Register new user
    print("TC1 register alice:", store.register_user("alice", "S3curePwd!"))

    # Test case 2: Duplicate registration
    print("TC2 register alice again:", store.register_user("alice", "AnotherPwd!"))

    # Test case 3: Correct login
    print("TC3 login alice correct:", store.verify_login("alice", "S3curePwd!"))

    # Test case 4: Wrong password
    print("TC4 login alice wrong:", store.verify_login("alice", "WrongPass!"))

    # Test case 5: Another user register and login
    print("TC5 register bob:", store.register_user("bob-01", "P@ssw0rd123"))
    print("TC5 login bob correct:", store.verify_login("bob-01", "P@ssw0rd123"))