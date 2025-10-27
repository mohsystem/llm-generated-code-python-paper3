import os
import hmac
import hashlib
import secrets
from dataclasses import dataclass
from typing import Dict, Optional

PBKDF2_ITERATIONS = 210_000
SALT_LEN = 16
DK_LEN = 32  # 256-bit

@dataclass
class User:
    username: str
    email: str
    salt: bytes
    hash: bytes
    iterations: int
    logged_in: bool = False

USERS: Dict[str, User] = {}

def validate_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    u = username.strip()
    if len(u) < 3 or len(u) > 50:
        return False
    for ch in u:
        if not (ch.isalnum() or ch in "_.-"):
            return False
    return True

def validate_email(email: str) -> bool:
    if not isinstance(email, str):
        return False
    e = email.strip()
    if len(e) < 6 or len(e) > 254:
        return False
    if " " in e:
        return False
    at = e.find("@")
    if at <= 0 or at != e.rfind("@"):
        return False
    local = e[:at]
    domain = e[at+1:]
    if not local or len(domain) < 3:
        return False
    if "." not in domain:
        return False
    return True

def is_strong_password(pw: str) -> bool:
    if not isinstance(pw, str):
        return False
    if len(pw) < 12 or len(pw) > 128:
        return False
    hasU = any(c.isupper() for c in pw)
    hasL = any(c.islower() for c in pw)
    hasD = any(c.isdigit() for c in pw)
    hasS = any(c in "!@#$%^&*()-_=+[]{};:,.?/\\|`~'\"<>" for c in pw)
    if any(c.isspace() for c in pw):
        return False
    return hasU and hasL and hasD and hasS

def pbkdf2_hash(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS, dklen: int = DK_LEN) -> bytes:
    # Avoid returning None; let exceptions propagate if inputs are invalid
    pw_bytes = password.encode("utf-8")
    try:
        return hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, iterations, dklen)
    finally:
        # Overwrite local variable
        ba = bytearray(pw_bytes)
        for i in range(len(ba)):
            ba[i] = 0

def register_user(username: str, email: str, password: str) -> bool:
    if not validate_username(username) or not validate_email(email):
        return False
    if not is_strong_password(password):
        return False
    if username in USERS:
        return False
    salt = secrets.token_bytes(SALT_LEN)
    h = pbkdf2_hash(password, salt, PBKDF2_ITERATIONS, DK_LEN)
    USERS[username] = User(username=username, email=email, salt=salt, hash=h, iterations=PBKDF2_ITERATIONS)
    return True

def verify_password(user: User, provided: str) -> bool:
    cand = pbkdf2_hash(provided, user.salt, user.iterations, DK_LEN)
    return hmac.compare_digest(user.hash, cand)

def login(username: str, password: str) -> bool:
    user = USERS.get(username)
    if user is None:
        return False
    ok = verify_password(user, password)
    if ok:
        user.logged_in = True
    return ok

def change_email(username: str, old_email: str, new_email: str, confirm_password: str) -> bool:
    user = USERS.get(username)
    if user is None:
        return False
    if not user.logged_in:
        return False
    if not (validate_email(old_email) and validate_email(new_email)):
        return False
    if user.email != old_email:
        return False
    if user.email == new_email:
        return False
    if not verify_password(user, confirm_password):
        return False
    user.email = new_email
    return True

def generate_strong_random_password(length: int = 16) -> str:
    if length < 12:
        length = 12
    lowers = "abcdefghijklmnopqrstuvwxyz"
    uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    symbols = "!@#$%^&*()-_=+[]{};:,.?/\\|`~'\"<>"
    allchars = lowers + uppers + digits + symbols
    # Ensure complexity
    pw = [
        secrets.choice(lowers),
        secrets.choice(uppers),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    for _ in range(length - 4):
        pw.append(secrets.choice(allchars))
    # Shuffle
    for i in range(len(pw) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pw[i], pw[j] = pw[j], pw[i]
    return "".join(pw)

if __name__ == "__main__":
    username = "alice"
    initial_email = "alice@example.com"
    strong_password = generate_strong_random_password(16)

    print("Register user:", register_user(username, initial_email, strong_password))

    # Test 1: change without login
    print("Test1 change without login (expect False):", change_email(username, initial_email, "alice_new@example.com", strong_password))

    # Test 2: login wrong password
    print("Test2 login wrong password (expect False):", login(username, "WrongPassw0rd!"))

    # Test 3: login correct password
    print("Test3 login correct password (expect True):", login(username, strong_password))

    # Test 4: change to same email
    print("Test4 change to same email (expect False):", change_email(username, initial_email, initial_email, strong_password))

    # Test 5: successful email change
    print("Test5 change email valid (expect True):", change_email(username, initial_email, "alice_secure@example.net", strong_password))