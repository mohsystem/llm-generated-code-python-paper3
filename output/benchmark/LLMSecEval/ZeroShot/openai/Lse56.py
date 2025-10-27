import os
import hmac
import hashlib
import re
from dataclasses import dataclass
from typing import Tuple

SALT_LEN = 16
HASH_LEN = 32
ITERATIONS = 100_000
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

@dataclass
class User:
    email: str
    salt: bytes
    pass_hash: bytes
    logged_in: bool = False

def is_email_valid(email: str) -> bool:
    return isinstance(email, str) and len(email) <= 320 and EMAIL_RE.match(email) is not None

def pbkdf2(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, dklen=HASH_LEN)

def constant_time_equals(a: bytes, b: bytes) -> bool:
    if a is None or b is None:
        return False
    return hmac.compare_digest(a, b)

def create_user(email: str, password: str) -> User:
    if not is_email_valid(email):
        raise ValueError("Invalid email")
    salt = os.urandom(SALT_LEN)
    ph = pbkdf2(password, salt)
    return User(email=email, salt=salt, pass_hash=ph, logged_in=False)

def login(user: User, password: str) -> bool:
    if user is None or password is None:
        return False
    ok = constant_time_equals(pbkdf2(password, user.salt), user.pass_hash)
    user.logged_in = ok
    return ok

def change_email(user: User, old_email: str, new_email: str, password: str, confirm_password: str) -> Tuple[bool, str]:
    if user is None:
        return False, "User not found"
    if not user.logged_in:
        return False, "User not logged in"
    if not old_email or not new_email or not password or not confirm_password:
        return False, "Missing parameters"
    if user.email != old_email:
        return False, "Old email does not match"
    if not is_email_valid(new_email):
        return False, "Invalid new email format"
    if old_email.lower() == new_email.lower():
        return False, "New email must be different from old email"
    if password != confirm_password:
        return False, "Password confirmation does not match"
    if not constant_time_equals(pbkdf2(password, user.salt), user.pass_hash):
        return False, "Authentication failed"
    user.email = new_email
    return True, "Email updated"

def main():
    # Test 1: Successful change
    u1 = create_user("alice@example.com", "Str0ngP@ss!")
    login(u1, "Str0ngP@ss!")
    print("Test1:", change_email(u1, "alice@example.com", "alice2@example.com", "Str0ngP@ss!", "Str0ngP@ss!"))

    # Test 2: Not logged in
    u2 = create_user("bob@example.com", "S3cure#Pass")
    print("Test2:", change_email(u2, "bob@example.com", "bob2@example.com", "S3cure#Pass", "S3cure#Pass"))

    # Test 3: Wrong password
    u3 = create_user("carol@example.com", "P@ssw0rd!")
    login(u3, "P@ssw0rd!")
    print("Test3:", change_email(u3, "carol@example.com", "carol2@example.com", "WrongPass!", "WrongPass!"))

    # Test 4: Wrong old email
    u4 = create_user("dave@example.com", "GoodP@ss1")
    login(u4, "GoodP@ss1")
    print("Test4:", change_email(u4, "notdave@example.com", "dave2@example.com", "GoodP@ss1", "GoodP@ss1"))

    # Test 5: New email same as old
    u5 = create_user("eve@example.com", "Sup3r#Pass")
    login(u5, "Sup3r#Pass")
    print("Test5:", change_email(u5, "eve@example.com", "eve@example.com", "Sup3r#Pass", "Sup3r#Pass"))

if __name__ == "__main__":
    main()