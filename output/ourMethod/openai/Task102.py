from __future__ import annotations
import hmac
import re
from dataclasses import dataclass
from typing import Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

SALT_LEN = 16
HASH_LEN = 32
ITERATIONS = 210_000
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")


@dataclass
class UserRecord:
    salt: bytes
    hash: bytes
    iterations: int


class UserDatabase:
    def __init__(self) -> None:
        self._records: Dict[str, UserRecord] = {}

    def create_user(self, username: str, password: str) -> bool:
        if not _valid_username(username) or not _strong_password(password) or username in self._records:
            return False
        salt = secrets.token_bytes(SALT_LEN)
        digest = _hash_password(password, salt, ITERATIONS, HASH_LEN)
        if digest is None:
            return False
        self._records[username] = UserRecord(salt=salt, hash=digest, iterations=ITERATIONS)
        return True

    def update_password(self, username: str, new_password: str) -> bool:
        if not _valid_username(username) or not _strong_password(new_password):
            return False
        rec = self._records.get(username)
        if rec is None:
            return False
        salt = secrets.token_bytes(SALT_LEN)
        digest = _hash_password(new_password, salt, ITERATIONS, HASH_LEN)
        if digest is None:
            return False
        self._records[username] = UserRecord(salt=salt, hash=digest, iterations=ITERATIONS)
        return True

    def verify(self, username: str, password: str) -> bool:
        if not _valid_username(username) or password is None:
            return False
        rec = self._records.get(username)
        if rec is None:
            return False
        digest = _hash_password(password, rec.salt, rec.iterations, HASH_LEN)
        if digest is None or len(digest) != len(rec.hash):
            return False
        return hmac.compare_digest(digest, rec.hash)


def _valid_username(username: Optional[str]) -> bool:
    return isinstance(username, str) and USERNAME_RE.fullmatch(username) is not None


def _strong_password(pwd: Optional[str]) -> bool:
    if not isinstance(pwd, str):
        return False
    if len(pwd) < 12 or len(pwd) > 128:
        return False
    has_l = any(c.islower() for c in pwd)
    has_u = any(c.isupper() for c in pwd)
    has_d = any(c.isdigit() for c in pwd)
    has_s = any(not c.isalnum() and not c.isspace() for c in pwd)
    no_ws = all(not c.isspace() for c in pwd)
    return has_l and has_u and has_d and has_s and no_ws


def _hash_password(password: str, salt: bytes, iterations: int, key_len: int) -> Optional[bytes]:
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_len,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode("utf-8"))
    except Exception:
        return None


def main() -> None:
    db = UserDatabase()
    # Create some initial users
    c1 = db.create_user("alice", "Start#Pass1234")
    c2 = db.create_user("bob_01", "Init$Secure5678")
    c3 = db.create_user("charlie_2", "My$trongPassw0rd!")
    c4 = db.create_user("dora", "DoraThe#Expl0rer")
    c5 = db.create_user("eve_user", "S3cure&EveUser!")
    print(f"Create users: {c1 and c2 and c3 and c4 and c5}")

    # Test 1: Successful update and verify
    t1u = db.update_password("alice", "NewStrong#Pass1234")
    t1v = db.verify("alice", "NewStrong#Pass1234")
    print(f"Test1 update+verify: {t1u and t1v}")

    # Test 2: Weak password rejected
    t2u = db.update_password("alice", "short")
    print(f"Test2 weak password rejected: {not t2u}")

    # Test 3: Non-existing user update
    t3u = db.update_password("unknown_user", "Valid#Password123")
    print(f"Test3 non-existing user: {not t3u}")

    # Test 4: Update bob and verify wrong password fails
    t4u = db.update_password("bob_01", "Another$trongP4ss!")
    t4v = db.verify("bob_01", "WrongPassword!234")
    print(f"Test4 update ok, wrong verify fails: {t4u and (not t4v)}")

    # Test 5: Long strong password
    long_pass = "A1!" + ("xY9#" * 20) + "Zz@2"
    t5u = db.update_password("charlie_2", long_pass)
    t5v = db.verify("charlie_2", long_pass)
    print(f"Test5 long password update+verify: {t5u and t5v}")


if __name__ == "__main__":
    main()