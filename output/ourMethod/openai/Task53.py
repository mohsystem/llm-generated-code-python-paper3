from __future__ import annotations
import hmac
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class User:
    username: str
    salt: bytes
    password_hash: bytes
    iterations: int
    password_changed_at: int  # epoch seconds


@dataclass(frozen=True)
class Session:
    username: str
    expires_at_ms: int


class Validators:
    @staticmethod
    def is_username_valid(username: str) -> bool:
        if not isinstance(username, str):
            return False
        if len(username) < 3 or len(username) > 32:
            return False
        for c in username:
            if not (c.isalnum() or c in "_-"):
                return False
        return True

    @staticmethod
    def is_password_strong(password: str) -> bool:
        if not isinstance(password, str):
            return False
        if len(password) < 12 or len(password) > 128:
            return False
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        specials = set("!@#$%^&*()_+-=[]{};':\",.<>/?\\|`~")
        has_special = any(c in specials for c in password)
        return has_lower and has_upper and has_digit and has_special


class Crypto:
    SALT_LEN = 16
    ITERATIONS = 120_000
    KEY_LEN = 32  # bytes

    @staticmethod
    def new_salt() -> bytes:
        return secrets.token_bytes(Crypto.SALT_LEN)

    @staticmethod
    def pbkdf2(password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=Crypto.KEY_LEN)

    @staticmethod
    def new_token() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def ct_eq(a: bytes, b: bytes) -> bool:
        return hmac.compare_digest(a, b)

    @staticmethod
    def ct_eq_str(a: Optional[str], b: Optional[str]) -> bool:
        a_b = (a or "").encode("utf-8")
        b_b = (b or "").encode("utf-8")
        return hmac.compare_digest(a_b, b_b)


class UserStore:
    def __init__(self) -> None:
        self._users: Dict[str, User] = {}

    def add_user(self, u: User) -> bool:
        if u.username in self._users:
            return False
        self._users[u.username] = u
        return True

    def get_user(self, username: str) -> Optional[User]:
        return self._users.get(username)

    def update_user(self, u: User) -> bool:
        if u.username not in self._users:
            return False
        self._users[u.username] = u
        return True


class SessionManager:
    def __init__(self, ttl_ms: int) -> None:
        self._ttl_ms = ttl_ms
        self._sessions: Dict[str, Session] = {}

    def create(self, username: str) -> str:
        token = Crypto.new_token()
        exp = int(time.time() * 1000) + self._ttl_ms
        self._sessions[token] = Session(username=username, expires_at_ms=exp)
        return token

    def validate(self, token: Optional[str]) -> bool:
        if token is None or len(token) < 10:
            return False
        s = self._sessions.get(token)
        if s is None:
            return False
        if int(time.time() * 1000) > s.expires_at_ms:
            del self._sessions[token]
            return False
        return True

    def get_username(self, token: Optional[str]) -> Optional[str]:
        if not self.validate(token):
            return None
        return self._sessions[token].username  # type: ignore[index]

    def logout(self, token: Optional[str]) -> bool:
        if token is None:
            return False
        return self._sessions.pop(token, None) is not None

    def rotate(self, token: Optional[str]) -> Optional[str]:
        if not self.validate(token):
            return None
        s = self._sessions.pop(token)  # type: ignore[index]
        new_token = Crypto.new_token()
        exp = int(time.time() * 1000) + self._ttl_ms
        self._sessions[new_token] = Session(username=s.username, expires_at_ms=exp)
        return new_token


class AuthService:
    def __init__(self, store: UserStore, sessions: SessionManager, pwd_expiry_days: int) -> None:
        self.store = store
        self.sessions = sessions
        self.pwd_expiry_days = pwd_expiry_days

    def register(self, username: str, password: str) -> bool:
        if not Validators.is_username_valid(username):
            return False
        if not Validators.is_password_strong(password):
            return False
        salt = Crypto.new_salt()
        pwd_hash = Crypto.pbkdf2(password, salt, Crypto.ITERATIONS)
        now = int(time.time())
        u = User(username=username, salt=salt, password_hash=pwd_hash, iterations=Crypto.ITERATIONS, password_changed_at=now)
        return self.store.add_user(u)

    def _pwd_expired(self, u: User) -> bool:
        max_age = self.pwd_expiry_days * 24 * 3600
        return (int(time.time()) - u.password_changed_at) > max_age

    def login(self, username: str, password: str) -> Optional[str]:
        if not Validators.is_username_valid(username):
            return None
        if not isinstance(password, str) or len(password) == 0:
            return None
        u = self.store.get_user(username)
        if u is None:
            return None
        calc = Crypto.pbkdf2(password, u.salt, u.iterations)
        if not Crypto.ct_eq(calc, u.password_hash):
            return None
        if self._pwd_expired(u):
            return None
        return self.sessions.create(username)

    def validate_session(self, token: Optional[str]) -> bool:
        return self.sessions.validate(token)

    def rotate_session(self, token: Optional[str]) -> Optional[str]:
        return self.sessions.rotate(token)

    def logout(self, token: Optional[str]) -> bool:
        return self.sessions.logout(token)

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        if not Validators.is_username_valid(username):
            return False
        if not Validators.is_password_strong(new_password):
            return False
        u = self.store.get_user(username)
        if u is None:
            return False
        calc = Crypto.pbkdf2(old_password, u.salt, u.iterations)
        if not Crypto.ct_eq(calc, u.password_hash):
            return False
        new_salt = Crypto.new_salt()
        new_hash = Crypto.pbkdf2(new_password, new_salt, Crypto.ITERATIONS)
        updated = User(username=username, salt=new_salt, password_hash=new_hash, iterations=Crypto.ITERATIONS, password_changed_at=int(time.time()))
        return self.store.update_user(updated)

    def get_username_from_session(self, token: Optional[str]) -> Optional[str]:
        return self.sessions.get_username(token)


def main() -> None:
    store = UserStore()
    sessions = SessionManager(ttl_ms=30 * 60 * 1000)  # 30 minutes
    auth = AuthService(store, sessions, pwd_expiry_days=90)

    # Test 1: Register with strong password
    t1 = auth.register("alice_user", "Str0ngP@ssw0rd!")
    print(f"Test1 register strong password: {t1}")

    # Test 2: Duplicate registration fails
    t2 = auth.register("alice_user", "An0ther$tr0ngPass!")
    print(f"Test2 duplicate register: {t2}")

    # Test 3: Wrong password fails
    bad_login = auth.login("alice_user", "WrongP@ssword123")
    print(f"Test3 login wrong password success? {bad_login is not None}")

    # Test 4: Login, validate, rotate
    token = auth.login("alice_user", "Str0ngP@ssw0rd!")
    valid_before = auth.validate_session(token)
    new_token = auth.rotate_session(token)
    old_valid_after = auth.validate_session(token)
    new_valid_after = auth.validate_session(new_token)
    print(f"Test4 login+validate before rotate: {valid_before}, old token valid after rotate: {old_valid_after}, new token valid after rotate: {new_valid_after}")

    # Test 5: Change password, old login fails, new login succeeds, logout invalidates session
    changed = auth.change_password("alice_user", "Str0ngP@ssw0rd!", "N3w$uperStr0ngP@ss!")
    old_try = auth.login("alice_user", "Str0ngP@ssw0rd!")
    new_try = auth.login("alice_user", "N3w$uperStr0ngP@ss!")
    logout_ok = auth.logout(new_try)
    valid_after_logout = auth.validate_session(new_try)
    print(f"Test5 change password: {changed}, old login success? {old_try is not None}, new login success? {new_try is not None}, logout ok: {logout_ok}, session valid after logout? {valid_after_logout}")


if __name__ == "__main__":
    main()