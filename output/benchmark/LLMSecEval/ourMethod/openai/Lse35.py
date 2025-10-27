import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Dict, Tuple

SALT_LEN = 16
HASH_LEN = 32  # 256-bit
ITERATIONS = 210_000
MAX_USERNAME_LEN = 50
MAX_PASSWORD_LEN = 128
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Login</title></head>
<body>
  <h1>Login</h1>
  <form action="/login" method="POST">
    <label>Username: <input type="text" name="username" maxlength="50" required></label><br>
    <label>Password: <input type="password" name="password" maxlength="128" required></label><br>
    <button type="submit">Login</button>
  </form>
</body>
</html>
"""

@dataclass
class UserRecord:
    salt_b64: str
    hash_b64: str

DATABASE: Dict[str, UserRecord] = {}

def _pbkdf2(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=HASH_LEN)

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > MAX_USERNAME_LEN:
        return False
    return USERNAME_RE.match(username) is not None

def is_strong_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) < 12 or len(password) > MAX_PASSWORD_LEN:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    if any(ord(c) < 32 for c in password):  # control chars
        return False
    return has_upper and has_lower and has_digit and has_special

def create_user(username: str, password: str) -> None:
    if not is_valid_username(username):
        raise ValueError("Invalid username")
    if not is_strong_password(password):
        raise ValueError("Weak password")
    if username in DATABASE:
        raise ValueError("User exists")
    salt = secrets.token_bytes(SALT_LEN)
    phash = _pbkdf2(password, salt)
    DATABASE[username] = UserRecord(
        salt_b64=base64.b64encode(salt).decode("ascii"),
        hash_b64=base64.b64encode(phash).decode("ascii"),
    )

def login(username: str, password: str) -> str:
    if not isinstance(username, str) or not isinstance(password, str):
        return "login.html"
    if len(username) < 3 or len(username) > MAX_USERNAME_LEN:
        return "login.html"
    if len(password) < 1 or len(password) > MAX_PASSWORD_LEN:
        return "login.html"
    if USERNAME_RE.match(username) is None:
        return "login.html"
    rec = DATABASE.get(username)
    if rec is None:
        return "login.html"
    salt = base64.b64decode(rec.salt_b64)
    expected = base64.b64decode(rec.hash_b64)
    computed = _pbkdf2(password, salt)
    ok = hmac.compare_digest(computed, expected)
    # Best-effort wipe
    del computed
    return "home.html" if ok else "login.html"

def get_login_html() -> str:
    return LOGIN_HTML

if __name__ == "__main__":
    print(get_login_html())

    # Prepare users
    create_user("user1", "StrongPassw0rd!")
    create_user("user2", "Compl3x!Pass#2")
    create_user("user3", "An0ther$trongOne")

    # 5 test cases
    tests = [
        ("user1", "StrongPassw0rd!"),  # home
        ("user2", "wrongPassword"),    # login
        ("nosuchuser", "Anything1!"),  # login
        ("bad user", "Compl3x!Pass#2"),# invalid username -> login
        ("user3", "x" * 129),          # too long password -> login
    ]
    for i, (u, p) in enumerate(tests, 1):
        print(f"Test {i}: {login(u, p)}")