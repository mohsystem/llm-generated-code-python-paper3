# Chain-of-Through process:
# 1) Problem: Provide user registration and authentication using secure password handling.
# 2) Security: Per-user random salt, PBKDF2-HMAC-SHA256, high iterations, constant-time compare.
# 3) Implementation: Use os.urandom, hashlib.pbkdf2_hmac, hmac.compare_digest.
# 4) Review: No plaintext storage, validate inputs, no global exposed secrets.
# 5) Output: Final secure code with 5 test cases.

import os
import hmac
import hashlib
from typing import Dict, Tuple

class UserAuth:
    def __init__(self, iterations: int = 200_000, salt_len: int = 16, dk_len: int = 32):
        self._db: Dict[str, Tuple[bytes, bytes, int]] = {}
        self._iterations = iterations
        self._salt_len = salt_len
        self._dk_len = dk_len

    def register_user(self, username: str, password: str) -> bool:
        if not self._valid_username(username) or not self._valid_password(password):
            return False
        if username in self._db:
            return False
        salt = os.urandom(self._salt_len)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self._iterations, dklen=self._dk_len)
        self._db[username] = (salt, dk, self._iterations)
        return True

    def authenticate(self, username: str, password: str) -> bool:
        rec = self._db.get(username)
        if not rec:
            return False
        salt, dk_stored, iters = rec
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters, dklen=len(dk_stored))
        ok = hmac.compare_digest(dk, dk_stored)
        return ok

    @staticmethod
    def _valid_username(u: str) -> bool:
        if not u or len(u) > 64:
            return False
        for c in u:
            if not (c.isalnum() or c in "._-"):
                return False
        return True

    @staticmethod
    def _valid_password(p: str) -> bool:
        return isinstance(p, str) and len(p) >= 8

if __name__ == "__main__":
    auth = UserAuth()
    t1 = auth.register_user("alice", "CorrectHorse1!") and auth.authenticate("alice", "CorrectHorse1!")
    t2 = not auth.authenticate("alice", "WrongHorse1!")
    t3 = not auth.register_user("alice", "CorrectHorse1!")
    t4 = auth.register_user("bob-01", "S3cureBob#2025") and auth.authenticate("bob-01", "S3cureBob#2025")
    t5 = not auth.authenticate("eve", "Another$Pass9")

    print("Test1 register+auth alice (expect True):", t1)
    print("Test2 wrong password (expect True):", t2)
    print("Test3 duplicate register (expect True):", t3)
    print("Test4 register+auth bob (expect True):", t4)
    print("Test5 non-existent user (expect True):", t5)