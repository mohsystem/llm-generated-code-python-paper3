# Chain-of-Through Steps embedded via comments.

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Optional, Tuple

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,189}\.[A-Za-z]{2,24}$")
MAX_EMAIL_LEN = 254

def is_valid_email(email: str) -> bool:
    if email is None:
        return False
    e = email.strip()
    if not e or len(e) > MAX_EMAIL_LEN:
        return False
    return EMAIL_REGEX.fullmatch(e) is not None

def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def hash_password(salt: bytes, password: str) -> bytes:
    if password is None:
        password = ""
    # Simple PBKDF-like: SHA256(salt || password || salt) then iterate
    digest = hashlib.sha256(salt + password.encode('utf-8') + salt).digest()
    for _ in range(999):
        digest = hashlib.sha256(digest + salt).digest()
    return digest

@dataclass
class User:
    username: str
    email: str
    salt: bytes
    password_hash: bytes

class AuthService:
    def __init__(self):
        self.current_user: Optional[User] = None

    @staticmethod
    def register_default_user(username: str, email: str, password: str) -> User:
        salt = os.urandom(16)
        return User(username=username, email=email, salt=salt, password_hash=hash_password(salt, password))

    def login(self, user: User, username: str, password: str) -> bool:
        if user is None or username is None or password is None:
            return False
        if user.username != username:
            return False
        computed = hash_password(user.salt, password)
        ok = constant_time_equals(user.password_hash, computed)
        if ok:
            self.current_user = user
            return True
        return False

    def logout(self) -> None:
        self.current_user = None

    def change_email(self, old_email: str, new_email: str, confirm_password: str) -> str:
        if self.current_user is None:
            return "Error: You must be logged in to change your email."
        if old_email is None or new_email is None or confirm_password is None:
            return "Error: Missing required fields."
        old_e = old_email.strip()
        new_e = new_email.strip()
        if not is_valid_email(old_e) or not is_valid_email(new_e):
            return "Error: Invalid email format."
        if self.current_user.email != old_e:
            return "Error: The provided old email does not match our records."
        if old_e.lower() == new_e.lower():
            return "Error: New email must be different from old email."
        # Verify password
        computed = hash_password(self.current_user.salt, confirm_password)
        if not constant_time_equals(self.current_user.password_hash, computed):
            return "Error: Invalid credentials."
        self.current_user.email = new_e
        return f"Success: Email changed to {new_e}."

def _user_snapshot(u: Optional[User]) -> str:
    if u is None:
        return "null"
    return f"User(username={u.username}, email={u.email}, salt_b64={u.salt.hex()})"

def main():
    user = AuthService.register_default_user("alice", "alice@old.com", "P@ssw0rd!")
    auth = AuthService()

    # Test 1: Successful login and email change
    login1 = auth.login(user, "alice", "P@ssw0rd!")
    res1 = auth.change_email("alice@old.com", "alice@new.com", "P@ssw0rd!")
    print(f"T1 login={login1} -> {res1} | {_user_snapshot(user)}")
    auth.logout()

    # Test 2: Attempt to change email while not logged in
    res2 = auth.change_email("alice@new.com", "alice@newer.com", "P@ssw0rd!")
    print(f"T2 -> {res2} | {_user_snapshot(user)}")

    # Test 3: Wrong password
    login3 = auth.login(user, "alice", "P@ssw0rd!")
    res3 = auth.change_email("alice@new.com", "alice@fresh.com", "WRONGPASS")
    print(f"T3 login={login3} -> {res3} | {_user_snapshot(user)}")
    auth.logout()

    # Test 4: New email equals old email
    login4 = auth.login(user, "alice", "P@ssw0rd!")
    res4 = auth.change_email("alice@new.com", "alice@new.com", "P@ssw0rd!")
    print(f"T4 login={login4} -> {res4} | {_user_snapshot(user)}")
    auth.logout()

    # Test 5: Old email mismatch
    login5 = auth.login(user, "alice", "P@ssw0rd!")
    res5 = auth.change_email("wrong@old.com", "alice@final.com", "P@ssw0rd!")
    print(f"T5 login={login5} -> {res5} | {_user_snapshot(user)}")
    auth.logout()

if __name__ == "__main__":
    main()