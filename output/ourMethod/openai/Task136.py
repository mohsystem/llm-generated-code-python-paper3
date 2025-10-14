from __future__ import annotations
import re
import time
import hmac
import secrets
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional

SALT_LEN = 16
HASH_LEN = 32
ITERATIONS = 210_000
PASSWORD_EXPIRATION_SECONDS = 90 * 24 * 60 * 60  # 90 days

@dataclass(frozen=True)
class User:
    username: str
    salt: bytes
    pwd_hash: bytes
    iterations: int
    created_at_epoch: int

class UserStore:
    def __init__(self) -> None:
        self._users: Dict[str, User] = {}

    def register_user(self, username: str, password: str) -> str:
        err = validate_username(username)
        if err:
            return f"ERROR: {err}"
        if username in self._users:
            return "ERROR: username already exists"
        perr = validate_password_policy(username, password)
        if perr:
            return f"ERROR: {perr}"
        salt = secrets.token_bytes(SALT_LEN)
        pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=HASH_LEN)
        user = User(username=username, salt=salt, pwd_hash=pwd_hash, iterations=ITERATIONS, created_at_epoch=int(time.time()))
        self._users[username] = user
        return "OK"

    def authenticate(self, username: str, password: str) -> bool:
        user = self._users.get(username)
        if user is None:
            simulate_work(password)
            return False
        if is_expired(user):
            simulate_work(password)
            return False
        test_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), user.salt, user.iterations, dklen=len(user.pwd_hash))
        return hmac.compare_digest(test_hash, user.pwd_hash)

def validate_username(username: str) -> Optional[str]:
    if not isinstance(username, str):
        return "username required"
    if len(username) < 3 or len(username) > 32:
        return "username length must be 3-32"
    if not re.fullmatch(r"[A-Za-z0-9_-]+", username):
        return "username may contain letters, digits, '_' or '-'"
    return None

def validate_password_policy(username: str, password: str) -> Optional[str]:
    if not isinstance(password, str):
        return "password required"
    if len(password) < 12 or len(password) > 128:
        return "password length must be 12-128"
    if not re.search(r"[a-z]", password):
        return "password must contain lower-case letter"
    if not re.search(r"[A-Z]", password):
        return "password must contain upper-case letter"
    if not re.search(r"\d", password):
        return "password must contain digit"
    if not re.search(r"[^\w\s]", password):
        return "password must contain special character"
    if username.lower() in password.lower():
        return "password must not contain the username"
    blacklist = {
        "password", "123456", "123456789", "qwerty", "letmein", "welcome", "admin", "iloveyou"
    }
    if password.lower() in blacklist:
        return "password too common"
    return None

def is_expired(user: User) -> bool:
    return int(time.time()) - user.created_at_epoch > PASSWORD_EXPIRATION_SECONDS

def simulate_work(password: str) -> None:
    salt = secrets.token_bytes(SALT_LEN)
    hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=HASH_LEN)

def main() -> None:
    store = UserStore()

    # Test 1: Register alice with strong password
    t1 = store.register_user("alice", "Str0ng!Passw0rd")
    print(f"Test1 register alice: {t1}")

    # Test 2: Authenticate alice with correct password
    t2 = store.authenticate("alice", "Str0ng!Passw0rd")
    print(f"Test2 auth alice correct: {t2}")

    # Test 3: Authenticate alice with wrong password
    t3 = store.authenticate("alice", "WrongPass!123")
    print(f"Test3 auth alice wrong: {t3}")

    # Test 4: Register bob with weak password
    t4 = store.register_user("bob", "password")
    print(f"Test4 register bob weak: {t4}")

    # Test 5: Register alice again (duplicate)
    t5 = store.register_user("alice", "An0ther$tr0ngOne")
    print(f"Test5 register alice duplicate: {t5}")

if __name__ == "__main__":
    main()