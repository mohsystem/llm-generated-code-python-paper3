import os
import re
import secrets
import hmac
import hashlib
from typing import Optional, Tuple, Dict

class User:
    def __init__(self, email: str, salt: bytes, pw_hash: bytes):
        self.email = email
        self.salt = salt
        self.pw_hash = pw_hash

class AuthService:
    SALT_LEN = 16
    HASH_LEN = 32
    PBKDF2_ITERS = 210_000

    def __init__(self) -> None:
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, str] = {}

    @staticmethod
    def valid_email(email: str) -> bool:
        if not isinstance(email, str):
            return False
        e = email.strip()
        if len(e) < 5 or len(e) > 254:
            return False
        return re.match(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$", e) is not None

    @staticmethod
    def strong_password(pwd: str) -> bool:
        if not isinstance(pwd, str) or len(pwd) < 10 or len(pwd) > 512:
            return False
        up = any(c.isupper() for c in pwd)
        lo = any(c.islower() for c in pwd)
        di = any(c.isdigit() for c in pwd)
        sp = any(not c.isalnum() for c in pwd)
        return up and lo and di and sp

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, AuthService.PBKDF2_ITERS, dklen=AuthService.HASH_LEN)

    def register(self, email: str, password: str) -> bool:
        if not self.valid_email(email) or not self.strong_password(password):
            return False
        key = email.lower()
        if key in self.users:
            return False
        salt = secrets.token_bytes(self.SALT_LEN)
        pw_hash = self._hash_password(password, salt)
        self.users[key] = User(email=email, salt=salt, pw_hash=pw_hash)
        return True

    def login(self, email: str, password: str) -> Optional[str]:
        if not self.valid_email(email) or not isinstance(password, str):
            return None
        key = email.lower()
        u = self.users.get(key)
        if not u:
            return None
        cand = self._hash_password(password, u.salt)
        if not hmac.compare_digest(cand, u.pw_hash):
            return None
        token = secrets.token_hex(16)
        self.sessions[token] = key
        return token

    def change_email(self, session_token: str, old_email: str, new_email: str, confirm_password: str) -> str:
        if not all(isinstance(x, str) for x in [session_token, old_email, new_email, confirm_password]):
            return "Invalid input"
        sess_email = self.sessions.get(session_token)
        if not sess_email:
            return "Not logged in"
        if not self.valid_email(old_email) or not self.valid_email(new_email):
            return "Invalid email"
        if old_email.lower() != sess_email:
            return "Session does not match user"
        if old_email.strip().lower() == new_email.strip().lower():
            return "New email must be different"
        u = self.users.get(old_email.lower())
        if not u:
            return "Email not found"
        cand = self._hash_password(confirm_password, u.salt)
        if not hmac.compare_digest(cand, u.pw_hash):
            return "Invalid credentials"
        if new_email.lower() in self.users:
            return "Email already in use"
        # Update records
        del self.users[old_email.lower()]
        u.email = new_email
        self.users[new_email.lower()] = u
        self.sessions[session_token] = new_email.lower()
        return "Email changed"

def main():
    svc = AuthService()
    pass1 = os.getenv("USER1_PASS") or "Str0ng!Passw0rd"
    pass2 = os.getenv("USER2_PASS") or "An0ther#Strong1"
    pass3 = os.getenv("USER3_PASS") or "Third#Str0ngP4ss"

    print("Register user1:", svc.register("alice@example.com", pass1))
    print("Register user2:", svc.register("bob@example.com", pass2))
    print("Duplicate register user1:", svc.register("alice@example.com", pass1))

    # 1) Successful change
    t1 = svc.login("alice@example.com", pass1)
    print("Login user1 ok:", t1 is not None)
    print("Change email success:", svc.change_email(t1 or "", "alice@example.com", "alice.new@example.com", pass1))

    # 2) Change without login
    print("Change without login:", svc.change_email("badtoken", "bob@example.com", "bob.new@example.com", pass2))

    # 3) Wrong old email for session
    t2 = svc.login("bob@example.com", pass2)
    print("Wrong old email:", svc.change_email(t2 or "", "alice.new@example.com", "bob.changed@example.com", pass2))

    # 4) Wrong confirm password
    print("Wrong password:", svc.change_email(t2 or "", "bob@example.com", "robert@example.com", "WrongP@ss1"))

    # 5) New email already in use
    print("Register user3:", svc.register("carol@example.com", pass3))
    print("Login user3 ok:", svc.login("carol@example.com", pass3) is not None)
    print("Email already used:", svc.change_email(t2 or "", "bob@example.com", "alice.new@example.com", pass2))

if __name__ == "__main__":
    main()