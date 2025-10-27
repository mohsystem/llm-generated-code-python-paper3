import os
import re
import secrets
import sys
import hmac
import hashlib
from typing import Optional, Tuple

PBKDF2_ITERATIONS = 210000
SALT_LEN = 16
HASH_LEN = 32  # bytes

class User:
    def __init__(self, username: str, email: str) -> None:
        self.username = username
        self.email = email
        self.salt: Optional[bytes] = None
        self.pwd_hash: Optional[bytes] = None
        self.logged_in: bool = False

def is_password_strong(pw: str) -> bool:
    if not isinstance(pw, str) or len(pw) < 12:
        return False
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_special = any(not c.isalnum() for c in pw)
    return has_upper and has_lower and has_digit and has_special

def is_email_valid(email: str) -> bool:
    if not isinstance(email, str) or len(email) < 5 or len(email) > 254:
        return False
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None

def pbkdf2(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not isinstance(salt, (bytes, bytearray)):
        return b""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=HASH_LEN)

def constant_time_equals(a: bytes, b: bytes) -> bool:
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        return False
    return hmac.compare_digest(a, b)

def set_password(user: User, password: str) -> bool:
    if user is None or not isinstance(password, str):
        return False
    if not is_password_strong(password):
        return False
    salt = secrets.token_bytes(SALT_LEN)
    pwd_hash = pbkdf2(password, salt)
    if not pwd_hash:
        return False
    user.salt = salt
    user.pwd_hash = pwd_hash
    return True

def verify_password(user: User, password: str) -> bool:
    if user is None or user.salt is None or user.pwd_hash is None:
        return False
    derived = pbkdf2(password, user.salt)
    return constant_time_equals(user.pwd_hash, derived)

def login(user: User, username: str, password: str) -> bool:
    if user is None or username != user.username:
        return False
    if verify_password(user, password):
        user.logged_in = True
        return True
    return False

def change_email(user: User, old_email: str, new_email: str, confirm_password: str) -> bool:
    if user is None or not isinstance(old_email, str) or not isinstance(new_email, str):
        return False
    if not user.logged_in:
        return False
    if old_email != user.email:
        return False
    if not is_email_valid(new_email):
        return False
    if not verify_password(user, confirm_password):
        return False
    user.email = new_email
    return True

def generate_strong_password(length: int = 16) -> str:
    if length < 12:
        length = 12
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    special = "!@#$%^&*()-_=+[]{};:,.?/|"
    all_chars = upper + lower + digits + special
    # Ensure policy requirements
    pw = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    for _ in range(length - 4):
        pw.append(secrets.choice(all_chars))
    # Shuffle
    for i in range(len(pw) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pw[i], pw[j] = pw[j], pw[i]
    return "".join(pw)

def main():
    user = User("alice", "alice@example.com")
    pw = generate_strong_password(16)
    if not set_password(user, pw):
        print("Setup failed")
        return

    # Test 1: Attempt change while not logged in -> False
    t1 = change_email(user, "alice@example.com", "newalice@example.com", pw)
    print(f"Test1 change while not logged in: {t1}")

    # Test 2: Login with correct password -> True
    t2 = login(user, "alice", pw)
    print(f"Test2 login with correct password: {t2}")

    # Test 3: Change with wrong old email -> False
    t3 = change_email(user, "wrong@example.com", "newalice@example.com", pw)
    print(f"Test3 change with wrong old email: {t3}")

    # Test 4: Change with wrong password -> False
    t4 = change_email(user, "alice@example.com", "newalice@example.com", "WrongPass!234")
    print(f"Test4 change with wrong password: {t4}")

    # Test 5: Change with correct old email and password -> True
    t5 = change_email(user, "alice@example.com", "newalice@example.com", pw)
    print(f"Test5 change with correct old email and password: {t5}")

if __name__ == "__main__":
    main()