# Chain-of-Through (comments only):
# 1) Problem understanding: implement login and email change with verification.
# 2) Security requirements: hash passwords (PBKDF2), constant-time compare, validate input.
# 3) Secure generation: use hashlib.pbkdf2_hmac, secrets for salt, regex for email, avoid sensitive prints.
# 4) Review: ensure validations and constant-time equality.
# 5) Output: final code with 5 test cases.

import re
import secrets
import hashlib
from typing import Dict, Optional

class User:
    def __init__(self, username: str, email: str, salt: bytes, pwd_hash: bytes):
        self.username = username
        self.email = email
        self.salt = salt
        self.pwd_hash = pwd_hash

class PasswordUtil:
    ITERATIONS = 120_000
    SALT_LEN = 16
    KEY_LEN = 32

    @staticmethod
    def new_salt() -> bytes:
        return secrets.token_bytes(PasswordUtil.SALT_LEN)

    @staticmethod
    def derive(password: str, salt: bytes) -> bytes:
        if password is None:
            raise ValueError("password is None")
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PasswordUtil.ITERATIONS, dklen=PasswordUtil.KEY_LEN)

    @staticmethod
    def ct_equal(a: bytes, b: bytes) -> bool:
        if a is None or b is None:
            return False
        if len(a) != len(b):
            # run full loop to keep time more constant
            maxlen = max(len(a), len(b))
            res = 0
            for i in range(maxlen):
                x = a[i] if i < len(a) else 0
                y = b[i] if i < len(b) else 0
                res |= (x ^ y)
            return False
        res = 0
        for x, y in zip(a, b):
            res |= (x ^ y)
        return res == 0

class UserStore:
    def __init__(self):
        self._by_username: Dict[str, User] = {}
        self._by_email: Dict[str, User] = {}

    def register_user(self, username: str, email: str, password: str) -> bool:
        if not username or not email or password is None:
            return False
        if username in self._by_username:
            return False
        if email.lower() in self._by_email:
            return False
        salt = PasswordUtil.new_salt()
        pwd_hash = PasswordUtil.derive(password, salt)
        u = User(username, email, salt, pwd_hash)
        self._by_username[username] = u
        self._by_email[email.lower()] = u
        return True

    def find_by_username(self, username: str) -> Optional[User]:
        return self._by_username.get(username)

    def find_by_email(self, email: str) -> Optional[User]:
        if email is None:
            return None
        return self._by_email.get(email.lower())

    def update_email(self, user: User, new_email: str) -> bool:
        if user is None or new_email is None:
            return False
        new_key = new_email.lower()
        if new_key in self._by_email:
            return False
        # remove old
        self._by_email.pop(user.email.lower(), None)
        user.email = new_email
        self._by_email[new_key] = user
        return True

class AuthService:
    EMAIL_RE = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$", re.IGNORECASE)

    def __init__(self, store: UserStore):
        self.store = store
        self.current_user: Optional[User] = None

    def is_logged_in(self) -> bool:
        return self.current_user is not None

    def login(self, username: str, password: str) -> bool:
        if username is None or password is None:
            return False
        u = self.store.find_by_username(username)
        if not u:
            return False
        derived = PasswordUtil.derive(password, u.salt)
        if PasswordUtil.ct_equal(derived, u.pwd_hash):
            self.current_user = u
            return True
        return False

    def logout(self):
        self.current_user = None

    @staticmethod
    def is_valid_email(email: str) -> bool:
        if email is None or len(email) > 254:
            return False
        return AuthService.EMAIL_RE.match(email) is not None

    def change_email(self, old_email: str, new_email: str, confirm_password: str) -> bool:
        if not self.is_logged_in():
            return False
        if old_email is None or new_email is None or confirm_password is None:
            return False
        if not self.is_valid_email(old_email) or not self.is_valid_email(new_email):
            return False
        if old_email.lower() != self.current_user.email.lower():
            return False
        if old_email.lower() == new_email.lower():
            return False
        derived = PasswordUtil.derive(confirm_password, self.current_user.salt)
        if not PasswordUtil.ct_equal(derived, self.current_user.pwd_hash):
            return False
        if self.store.find_by_email(old_email) is None:
            return False
        if self.store.find_by_email(new_email) is not None:
            return False
        return self.store.update_email(self.current_user, new_email)

def main():
    store = UserStore()
    auth = AuthService(store)

    store.register_user("alice", "alice@example.com", "StrongPass!1")
    store.register_user("bob", "bob@example.com", "CorrectHorseBatteryStaple")

    # Test 1: success
    t1login = auth.login("alice", "StrongPass!1")
    t1change = auth.change_email("alice@example.com", "alice.new@example.com", "StrongPass!1")
    print("Test1 success=" + str(t1login and t1change))
    auth.logout()

    # Test 2: change without login should fail
    t2 = auth.change_email("bob@example.com", "bob.new@example.com", "CorrectHorseBatteryStaple")
    print("Test2 success=" + str(not t2))

    # Test 3: wrong old email
    t3login = auth.login("bob", "CorrectHorseBatteryStaple")
    t3change = auth.change_email("wrongbob@example.com", "bob.new@example.com", "CorrectHorseBatteryStaple")
    print("Test3 success=" + str(t3login and (not t3change)))
    auth.logout()

    # Test 4: wrong confirm password
    t4login = auth.login("bob", "CorrectHorseBatteryStaple")
    t4change = auth.change_email("bob@example.com", "bob.new@example.com", "wrongpassword")
    print("Test4 success=" + str(t4login and (not t4change)))
    auth.logout()

    # Test 5: new email taken and invalid
    t5login = auth.login("bob", "CorrectHorseBatteryStaple")
    t5taken = auth.change_email("bob@example.com", "alice.new@example.com", "CorrectHorseBatteryStaple")
    t5invalid = auth.change_email("bob@example.com", "not-an-email", "CorrectHorseBatteryStaple")
    print("Test5 success=" + str(t5login and (not t5taken) and (not t5invalid)))
    auth.logout()

if __name__ == "__main__":
    main()