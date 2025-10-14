from __future__ import annotations
import time
import secrets
import hmac
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional

ITERATIONS = 210_000
SALT_LEN = 16
KEY_LEN = 32
TOKEN_LEN = 32
TOKEN_TTL = 15 * 60  # seconds

@dataclass
class UserRecord:
    username: str
    salt: bytes
    pwd_hash: bytes
    pwd_changed_at: int
    token_salt: Optional[bytes] = None
    token_hash: Optional[bytes] = None
    token_expiry: int = 0

class PasswordManager:
    def __init__(self) -> None:
        self.db: Dict[str, UserRecord] = {}

    @staticmethod
    def _validate_username(username: str) -> bool:
        if not isinstance(username, str):
            return False
        if len(username) < 3 or len(username) > 32:
            return False
        for c in username:
            if not (c.isalnum() or c == "_"):
                return False
        return True

    @staticmethod
    def _is_strong_password(password: str, username: str) -> bool:
        if not isinstance(password, str):
            return False
        if len(password) < 12 or len(password) > 128:
            return False
        up = any(c.isupper() for c in password)
        lo = any(c.islower() for c in password)
        di = any(c.isdigit() for c in password)
        sp = any(not c.isalnum() and not c.isspace() for c in password)
        if any(c.isspace() for c in password):
            return False
        if not (up and lo and di and sp):
            return False
        if username and username.lower() in password.lower():
            return False
        common = ["password","123456","qwerty","letmein","admin","welcome","iloveyou","monkey","abc123"]
        if any(w in password.lower() for w in common):
            return False
        return True

    @staticmethod
    def _pbkdf2(data: bytes, salt: bytes, iterations: int = ITERATIONS, dklen: int = KEY_LEN) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", data, salt, iterations, dklen=dklen)

    @staticmethod
    def _hex_encode(b: bytes) -> str:
        return b.hex()

    @staticmethod
    def _hex_decode(s: str) -> Optional[bytes]:
        try:
            if len(s) % 2 != 0:
                return None
            return bytes.fromhex(s)
        except ValueError:
            return None

    def register_user(self, username: str, password: str) -> bool:
        if not self._validate_username(username) or not self._is_strong_password(password, username):
            return False
        if username in self.db:
            return False
        salt = secrets.token_bytes(SALT_LEN)
        pwd_hash = self._pbkdf2(password.encode("utf-8"), salt)
        self.db[username] = UserRecord(username=username, salt=salt, pwd_hash=pwd_hash, pwd_changed_at=int(time.time()))
        return True

    def authenticate(self, username: str, password: str) -> bool:
        if not self._validate_username(username) or not isinstance(password, str):
            return False
        u = self.db.get(username)
        if not u:
            return False
        derived = self._pbkdf2(password.encode("utf-8"), u.salt)
        return hmac.compare_digest(derived, u.pwd_hash)

    def request_password_reset(self, username: str) -> str:
        if not self._validate_username(username):
            return ""
        u = self.db.get(username)
        if not u:
            return ""
        token = secrets.token_bytes(TOKEN_LEN)
        token_salt = secrets.token_bytes(SALT_LEN)
        token_hash = self._pbkdf2(token, token_salt)
        u.token_salt = token_salt
        u.token_hash = token_hash
        u.token_expiry = int(time.time()) + TOKEN_TTL
        return self._hex_encode(token)

    def reset_password(self, username: str, token_hex: str, new_password: str) -> bool:
        if not self._validate_username(username) or not isinstance(token_hex, str) or not isinstance(new_password, str):
            return False
        u = self.db.get(username)
        if not u or u.token_hash is None or u.token_salt is None:
            return False
        if int(time.time()) > u.token_expiry:
            return False
        token = self._hex_decode(token_hex)
        if token is None or len(token) != TOKEN_LEN:
            return False
        provided_hash = self._pbkdf2(token, u.token_salt)
        if not hmac.compare_digest(provided_hash, u.token_hash):
            return False
        if not self._is_strong_password(new_password, username):
            return False
        # Prevent reusing the same password
        new_derived_with_old_salt = self._pbkdf2(new_password.encode("utf-8"), u.salt)
        if hmac.compare_digest(new_derived_with_old_salt, u.pwd_hash):
            return False
        # Update password with fresh salt
        new_salt = secrets.token_bytes(SALT_LEN)
        new_hash = self._pbkdf2(new_password.encode("utf-8"), new_salt)
        u.salt = new_salt
        u.pwd_hash = new_hash
        u.pwd_changed_at = int(time.time())
        u.token_salt = None
        u.token_hash = None
        u.token_expiry = 0
        return True

def main() -> None:
    pm = PasswordManager()
    t1 = pm.register_user("alice", "Str0ng!Passw0rd")
    t2 = pm.authenticate("alice", "Str0ng!Passw0rd")
    token = pm.request_password_reset("alice")
    t3 = pm.reset_password("alice", token, "An0ther!StrongPwd") and pm.authenticate("alice", "An0ther!StrongPwd")
    t4 = pm.reset_password("alice", "deadbeef", "Yet@N0therStrong1")
    token2 = pm.request_password_reset("alice")
    t5 = pm.reset_password("alice", token2, "weakpass")
    print("Test1_RegisterStrongPassword:", t1)
    print("Test2_AuthenticateCorrect:", t2)
    print("Test3_ResetWithValidTokenAndAuth:", t3)
    print("Test4_ResetWithInvalidToken:", t4)
    print("Test5_AttemptWeakPasswordReset:", t5)

if __name__ == "__main__":
    main()