import re
import secrets
import hmac
import hashlib
from dataclasses import dataclass
from typing import Dict

MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
ITERATIONS = 210_000
SALT_LEN = 16
HASH_LEN = 32  # 256-bit


@dataclass
class User:
    username: str
    salt: bytes
    hash: bytes
    iterations: int


USERS: Dict[str, User] = {}


def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    return USERNAME_RE.fullmatch(username) is not None


def is_valid_password_input(password: str) -> bool:
    if not isinstance(password, str):
        return False
    return MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN


def derive(password: str, salt: bytes, iterations: int = ITERATIONS, dklen: int = HASH_LEN) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=dklen)


def create_user(username: str, password: str) -> bool:
    if not is_valid_username(username) or not is_valid_password_input(password):
        return False
    salt = secrets.token_bytes(SALT_LEN)
    pwd_hash = derive(password, salt, ITERATIONS, HASH_LEN)
    USERS[username] = User(username=username, salt=salt, hash=pwd_hash, iterations=ITERATIONS)
    return True


def verify_login(username: str, password: str) -> bool:
    if not is_valid_username(username) or not is_valid_password_input(password):
        return False
    user = USERS.get(username)
    if not user:
        return False
    comp = derive(password, user.salt, user.iterations, HASH_LEN)
    return hmac.compare_digest(comp, user.hash)


# Public API
def login(username: str, password: str) -> str:
    if verify_login(username, password):
        return "Redirect:/session"
    return "Invalid username or password."


def generate_strong_password(length: int = 16) -> str:
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    special = "!@#$%^&*()-_=+[]{}:,.?/~"
    all_chars = upper + lower + digits + special
    # ensure complexity
    pw = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    for _ in range(max(0, length - 4)):
        pw.append(secrets.choice(all_chars))
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw[:length])


if __name__ == "__main__":
    # Setup user
    test_user = "alice"
    correct_pwd = generate_strong_password(16)
    ok = create_user(test_user, correct_pwd)
    if not ok:
        print("User setup failed")
        raise SystemExit(1)

    # 5 test cases
    tests = [
        (test_user, correct_pwd),     # correct
        (test_user, "WrongPass!123"), # wrong password
        ("bob", "Anything123!"),      # non-existent
        ("", "short"),                # invalid username
        ("al", "Password!234"),       # too short username
    ]
    for i, (u, p) in enumerate(tests, 1):
        print(f"Test {i}: {login(u, p)}")