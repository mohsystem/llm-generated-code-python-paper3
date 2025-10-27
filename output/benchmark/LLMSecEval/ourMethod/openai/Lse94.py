import base64
import hashlib
import hmac
import re
import secrets
from typing import Optional, Dict, Any


PBKDF2_ITERATIONS = 210_000
SALT_LEN = 16
DK_LEN = 32
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")


class InMemoryDatabase:
    def __init__(self) -> None:
        self._users: Dict[str, Dict[str, Any]] = {}

    def insert(self, record: Dict[str, Any]) -> bool:
        username = record.get("username")
        if username in self._users:
            return False
        self._users[username] = record
        return True

    def get(self, username: str) -> Optional[Dict[str, Any]]:
        return self._users.get(username)

    def size(self) -> int:
        return len(self._users)


def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if not 3 <= len(username) <= 32:
        return False
    return bool(USERNAME_RE.fullmatch(username))


def is_strong_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) < 12:
        return False
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_space = any(c.isspace() for c in password)
    has_special = any(not c.isalnum() and not c.isspace() for c in password)
    if has_space:
        return False
    return has_lower and has_upper and has_digit and has_special


def hash_password_with_new_salt(password: str) -> Dict[str, Any]:
    salt = secrets.token_bytes(SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=DK_LEN)
    record = {
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "hash_b64": base64.b64encode(dk).decode("ascii"),
        "iterations": PBKDF2_ITERATIONS,
    }
    # zeroize local variables where possible
    # note: Python strings/bytes are immutable; we avoid keeping them around
    return record


def register_user(db: InMemoryDatabase, username: str, password: str) -> Optional[Dict[str, Any]]:
    if db is None:
        return None
    if not is_valid_username(username):
        return None
    if not is_strong_password(password):
        return None

    record_parts = hash_password_with_new_salt(password)
    record = {
        "username": username,
        "salt_b64": record_parts["salt_b64"],
        "hash_b64": record_parts["hash_b64"],
        "iterations": record_parts["iterations"],
    }
    if not db.insert(record):
        return None
    return record


def _ct_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def main():
    db = InMemoryDatabase()

    tests = [
        ("alice_01", "Sup3rStr0ng!Pwd"),
        ("bobUser_22", "An0ther$trongPass!"),
        ("x", "Short!1A"),
        ("charlie_33", "NoSpacesAllowed!9"),
        ("alice_01", "Sup3rStr0ng!Pwd"),
    ]

    for i, (u, p) in enumerate(tests, 1):
        rec = register_user(db, u, p)
        print(f"Test {i} - username={u} -> {'stored' if rec else 'rejected'}")

    print(f"Total stored users: {db.size()}")
    alice = db.get("alice_01")
    if alice:
        print(
            "Stored record for alice_01: "
            f"iterations={alice['iterations']}, salt(len)={len(alice['salt_b64'])}, hash(len)={len(alice['hash_b64'])}"
        )


if __name__ == "__main__":
    main()