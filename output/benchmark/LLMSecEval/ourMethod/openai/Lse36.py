import os
import sys
import time
import hmac
import secrets
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional

SALT_LEN = 16
HASH_LEN = 32
PBKDF2_ITERATIONS = 210_000
PASSWORD_MAX_AGE_SECONDS = 90 * 24 * 60 * 60
REDIRECT_URL = "https://example.com/home"
MAX_PASSWORD_LEN = 256

@dataclass
class User:
    username: str
    salt: bytes
    password_hash: bytes
    iterations: int
    created_at: int  # epoch seconds

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 64:
        return False
    for ch in username:
        if not (ch.isalnum() or ch in "_.-"):
            return False
    return True

def is_strong_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) < 12 or len(password) > MAX_PASSWORD_LEN:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    specials = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~\\ "
    has_special = any(c in specials for c in password)
    return has_upper and has_lower and has_digit and has_special

def pbkdf2(password_bytes: bytes, salt: bytes, iterations: int, dklen: int = HASH_LEN) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password_bytes, salt, iterations, dklen=dklen)

def create_user(db: Dict[str, User], username: str, password: str) -> bool:
    if not is_valid_username(username):
        return False
    if not is_strong_password(password):
        return False
    salt = secrets.token_bytes(SALT_LEN)
    pw_bytes = bytearray(password.encode('utf-8'))
    try:
        pwd_hash = pbkdf2(pw_bytes, salt, PBKDF2_ITERATIONS)
    finally:
        for i in range(len(pw_bytes)):
            pw_bytes[i] = 0
    u = User(username=username, salt=salt, password_hash=pwd_hash, iterations=PBKDF2_ITERATIONS, created_at=int(time.time()))
    if username in db:
        return False
    db[username] = u
    return True

def login(db: Dict[str, User], username: str, password: str) -> Optional[str]:
    if not is_valid_username(username):
        return None
    if not isinstance(password, str) or len(password) == 0 or len(password) > MAX_PASSWORD_LEN:
        return None
    user = db.get(username)
    if user is None:
        return None
    pw_bytes = bytearray(password.encode('utf-8'))
    try:
        computed = pbkdf2(pw_bytes, user.salt, user.iterations)
    finally:
        for i in range(len(pw_bytes)):
            pw_bytes[i] = 0
    if not hmac.compare_digest(computed, user.password_hash):
        return None
    if int(time.time()) > user.created_at + PASSWORD_MAX_AGE_SECONDS:
        return None
    return REDIRECT_URL

def generate_strong_password(length: int = 16) -> str:
    if length < 12:
        length = 12
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    special = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~\\"
    # Ensure at least one of each
    pwd_chars = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    allchars = upper + lower + digits + special
    for _ in range(length - 4):
        pwd_chars.append(secrets.choice(allchars))
    # Shuffle
    for i in range(len(pwd_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pwd_chars[i], pwd_chars[j] = pwd_chars[j], pwd_chars[i]
    return "".join(pwd_chars)

def main():
    db: Dict[str, User] = {}

    # Test 1: Create user and successful login
    user1 = "alice_1"
    pass1 = generate_strong_password(16)
    created1 = create_user(db, user1, pass1)
    res1 = login(db, user1, pass1)
    print(f"Test1_created={created1} loginSuccess={res1 == REDIRECT_URL}")

    # Test 2: Wrong password
    res2 = login(db, user1, "WrongPass123!")
    print(f"Test2_wrongPassword={res2 is None}")

    # Test 3: Non-existent user
    res3 = login(db, "nonexistent", "SomeStrong!2345")
    print(f"Test3_nonexistent={res3 is None}")

    # Test 4: Invalid username format
    res4 = login(db, "../baduser", "ValidPass!2345")
    print(f"Test4_invalidUsername={res4 is None}")

    # Test 5: Expired password
    user2 = "bob-2"
    pass2 = generate_strong_password(18)
    created2 = create_user(db, user2, pass2)
    if user2 in db:
        db[user2].created_at = int(time.time()) - (PASSWORD_MAX_AGE_SECONDS + 3600)
    res5 = login(db, user2, pass2)
    print(f"Test5_expiredPassword_userCreated={created2} loginBlocked={res5 is None}")

if __name__ == "__main__":
    main()