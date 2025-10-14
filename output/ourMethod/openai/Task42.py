import re
import time
import hmac
import secrets
import hashlib
from typing import Dict, Tuple

class AuthSystem:
    SALT_LEN = 16
    KEY_LEN = 32
    ITERATIONS = 210_000
    PASSWORD_MAX_AGE_SECONDS = 90 * 24 * 60 * 60  # 90 days

    def __init__(self) -> None:
        # users: username -> record dict
        self.users: Dict[str, Dict[str, object]] = {}

    @staticmethod
    def _valid_username(username: str) -> bool:
        if not isinstance(username, str):
            return False
        if len(username) < 1 or len(username) > 32:
            return False
        return re.fullmatch(r"[A-Za-z0-9_]+", username) is not None

    @staticmethod
    def _strong_password(password: str) -> bool:
        if not isinstance(password, str) or len(password) < 12:
            return False
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any((33 <= ord(c) <= 126) and not c.isalnum() for c in password)
        return has_lower and has_upper and has_digit and has_special

    @staticmethod
    def _pbkdf2(password: str, salt: bytes, iterations: int, dklen: int) -> bytes:
        # Avoid logging secrets
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=dklen)

    def register_user(self, username: str, password: str) -> bool:
        if not self._valid_username(username):
            return False
        if not self._strong_password(password):
            return False
        if username in self.users:
            return False
        salt = secrets.token_bytes(self.SALT_LEN)
        key = self._pbkdf2(password, salt, self.ITERATIONS, self.KEY_LEN)
        self.users[username] = {
            "salt": salt,
            "hash": key,
            "iterations": self.ITERATIONS,
            "created": int(time.time()),
        }
        return True

    # Returns: 0=success, 1=invalid credentials, 2=password expired
    def authenticate(self, username: str, password: str) -> int:
        rec = self.users.get(username)
        if rec is None:
            return 1
        derived = self._pbkdf2(password, rec["salt"], rec["iterations"], len(rec["hash"]))
        if not hmac.compare_digest(derived, rec["hash"]):
            return 1
        if int(time.time()) - int(rec["created"]) > self.PASSWORD_MAX_AGE_SECONDS:
            return 2
        return 0

    def update_password(self, username: str, new_password: str) -> bool:
        if not self._strong_password(new_password):
            return False
        rec = self.users.get(username)
        if rec is None:
            return False
        salt = secrets.token_bytes(self.SALT_LEN)
        key = self._pbkdf2(new_password, salt, self.ITERATIONS, self.KEY_LEN)
        rec["salt"] = salt
        rec["hash"] = key
        rec["iterations"] = self.ITERATIONS
        rec["created"] = int(time.time())
        return True

    # Test helper only
    def force_expire_user(self, username: str, seconds_ago: int) -> bool:
        rec = self.users.get(username)
        if rec is None:
            return False
        rec["created"] = int(time.time()) - abs(int(seconds_ago))
        return True

def run_tests() -> Tuple[bool, ...]:
    auth = AuthSystem()

    # Test 1: Register and authenticate
    r1 = auth.register_user("alice", "Str0ng!Passw0rd")
    a1 = auth.authenticate("alice", "Str0ng!Passw0rd")

    # Test 2: Weak password rejected
    r2 = auth.register_user("bob", "password")

    # Test 3: Wrong password
    r3 = auth.register_user("carol", "C0mpl3x#Pass123")
    a3 = auth.authenticate("carol", "wrongPASS!")

    # Test 4: Expired password
    r4 = auth.register_user("dave", "Secur3!Passw0rd")
    f4 = auth.force_expire_user("dave", 200 * 24 * 60 * 60)
    a4 = auth.authenticate("dave", "Secur3!Passw0rd")

    # Test 5: Update password and authenticate
    r5 = auth.register_user("erin", "Init!Passw0rd1")
    u5 = auth.update_password("erin", "New!Passw0rd2")
    a5_new = auth.authenticate("erin", "New!Passw0rd2")
    a5_old = auth.authenticate("erin", "Init!Passw0rd1")

    return (
        r1 and a1 == 0,
        r2 is False,
        r3 and a3 == 1,
        r4 and f4 and a4 == 2,
        r5 and u5 and a5_new == 0 and a5_old == 1,
    )

if __name__ == "__main__":
    results = run_tests()
    for i, ok in enumerate(results, 1):
        print(f"Test{i}={ok}")