import os
import hmac
import hashlib
import re
from typing import Optional, Dict

class UserStore:
    def __init__(self, iterations: int = 120_000, salt_len: int = 16, key_len: int = 32, max_failed: int = 5):
        self._users: Dict[str, Dict] = {}
        self.iterations = iterations
        self.salt_len = salt_len
        self.key_len = key_len
        self.max_failed = max_failed
        self._dummy_salt = os.urandom(self.salt_len)

    def _valid_username(self, username: str) -> bool:
        if not isinstance(username, str):
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", username))

    def _valid_password(self, password: str) -> bool:
        if not isinstance(password, str):
            return False
        if len(password) < 8 or len(password) > 128:
            return False
        has_letter = any(c.isalpha() for c in password)
        has_digit = any(c.isdigit() for c in password)
        return has_letter and has_digit

    def _pbkdf2(self, password: str, salt: bytes, iterations: int) -> bytes:
        # UTF-8 encode password
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=self.key_len)

    def register_user(self, username: str, password: str) -> bool:
        if not self._valid_username(username) or not self._valid_password(password):
            return False
        if username in self._users:
            return False
        salt = os.urandom(self.salt_len)
        phash = self._pbkdf2(password, salt, self.iterations)
        self._users[username] = {
            "salt": salt,
            "iter": self.iterations,
            "hash": phash,
            "failed": 0,
            "locked": False,
        }
        return True

    def authenticate(self, username: str, password: str) -> bool:
        rec = self._users.get(username)
        if rec is None:
            # dummy work to mitigate timing/enum
            dummy = self._pbkdf2(password, self._dummy_salt, self.iterations)
            hmac.compare_digest(dummy, self._dummy_salt)
            return False
        if rec["locked"]:
            dummy = self._pbkdf2(password, rec["salt"], rec["iter"])
            hmac.compare_digest(dummy, rec["hash"])
            return False
        computed = self._pbkdf2(password, rec["salt"], rec["iter"])
        ok = hmac.compare_digest(computed, rec["hash"])
        if ok:
            rec["failed"] = 0
            return True
        else:
            rec["failed"] += 1
            if rec["failed"] >= self.max_failed:
                rec["locked"] = True
            return False

    def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        rec = self._users.get(username)
        if rec is None or rec["locked"]:
            return False
        computed = self._pbkdf2(current_password, rec["salt"], rec["iter"])
        if not hmac.compare_digest(computed, rec["hash"]):
            return False
        if not self._valid_password(new_password):
            return False
        new_salt = os.urandom(self.salt_len)
        new_hash = self._pbkdf2(new_password, new_salt, self.iterations)
        rec["salt"] = new_salt
        rec["hash"] = new_hash
        rec["iter"] = self.iterations
        rec["failed"] = 0
        rec["locked"] = False
        return True

    def is_locked(self, username: str) -> bool:
        rec = self._users.get(username)
        return bool(rec and rec["locked"])

    def failed_attempts(self, username: str) -> int:
        rec = self._users.get(username)
        return -1 if rec is None else rec["failed"]

def run_tests():
    store = UserStore()

    # 1) Register and authenticate successfully
    reg1 = store.register_user("alice", "CorrectHorseBatteryStaple1!")
    auth1 = store.authenticate("alice", "CorrectHorseBatteryStaple1!")
    print(f"Test1 register alice: {reg1}, auth success: {auth1}")

    # 2) Wrong password attempt
    auth_wrong = store.authenticate("alice", "WrongPassword123")
    print(f"Test2 auth wrong password: {auth_wrong}, failed attempts: {store.failed_attempts('alice')}")

    # 3) Lock account after repeated failures
    for i in range(4):
        store.authenticate("alice", f"Wrong{i}Pass1")
    print(f"Test3 locked: {store.is_locked('alice')}")
    auth_after_lock = store.authenticate("alice", "CorrectHorseBatteryStaple1!")
    print(f"Test3 auth after lock (should be False): {auth_after_lock}")

    # 4) Register bob and change password successfully
    reg2 = store.register_user("bob_01", "InitPassw0rd!")
    change = store.change_password("bob_01", "InitPassw0rd!", "N3wSecur3Pass!")
    auth_old = store.authenticate("bob_01", "InitPassw0rd!")
    auth_new = store.authenticate("bob_01", "N3wSecur3Pass!")
    print(f"Test4 bob register: {reg2}, change: {change}, old auth: {auth_old}, new auth: {auth_new}")

    # 5) Duplicate user registration
    dup = store.register_user("alice", "AnotherPass1!")
    print(f"Test5 duplicate register alice: {dup}")

if __name__ == "__main__":
    run_tests()