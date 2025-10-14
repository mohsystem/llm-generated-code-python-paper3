from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from typing import Dict, Tuple

from secrets import token_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore


SALT_LEN = 16
ITERATIONS = 210_000
DK_LEN = 32  # 256-bit
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass(frozen=True)
class UserRecord:
    salt: bytes
    phash: bytes
    iterations: int


class UserStore:
    def __init__(self) -> None:
        self._users: Dict[str, UserRecord] = {}

    def signup(self, username: str, password: str) -> bool:
        if not isinstance(username, str) or not isinstance(password, str):
            return False
        if not self._valid_username(username):
            return False
        ok, _ = self._validate_password_policy(password)
        if not ok:
            return False
        if username in self._users:
            return False

        salt = token_bytes(SALT_LEN)
        phash = self._pbkdf2(password.encode("utf-8"), salt, ITERATIONS, DK_LEN)
        # Store salted hash; do not store plaintext
        self._users[username] = UserRecord(salt=salt, phash=phash, iterations=ITERATIONS)
        return True

    @staticmethod
    def _valid_username(username: str) -> bool:
        if len(username) < 1 or len(username) > 64:
            return False
        return USERNAME_RE.fullmatch(username) is not None

    @staticmethod
    def _validate_password_policy(password: str) -> Tuple[bool, str]:
        if len(password) < 12 or len(password) > 128:
            return False, "length"
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        specials = set("!@#$%^&*()-_=+[]{};:'\",.<>/?`~\\|")
        has_special = any(c in specials for c in password)
        if any(ord(c) == 0 or (ord(c) < 32) for c in password):
            return False, "invalid-char"
        if not (has_upper and has_lower and has_digit and has_special):
            return False, "complexity"
        return True, "ok"

    @staticmethod
    def _pbkdf2(password: bytes, salt: bytes, iterations: int, dk_len: int) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=dk_len,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password)


def main() -> None:
    store = UserStore()

    tests = [
        ("alice", "ValidPassw0rd!"),   # success
        ("bob", "short"),              # fail: weak
        ("alice", "AnotherValid1!"),   # fail: duplicate
        ("carol", "Another$trong1"),   # success
        ("dave", "NoSpecialChar1"),    # fail: missing special
    ]

    for u, p in tests:
        res = store.signup(u, p)
        print(f"{u}: {'signup ok' if res else 'signup failed'}")


if __name__ == "__main__":
    main()