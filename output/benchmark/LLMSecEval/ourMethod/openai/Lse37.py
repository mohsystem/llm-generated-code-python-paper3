import os
import re
import secrets
import sys
import hmac
import hashlib
from typing import Dict, Tuple

class AuthService:
    def __init__(self) -> None:
        self._db: Dict[str, Tuple[bytes, bytes, int]] = {}  # username -> (salt, hash, iterations)
        self._username_re = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
        self._min_pw = 8
        self._max_pw = 128
        self._iterations = 210_000
        self._dklen = 32

    def _validate_username(self, username: str) -> bool:
        if not isinstance(username, str):
            return False
        if len(username) < 1 or len(username) > 64:
            return False
        return bool(self._username_re.fullmatch(username))

    def _validate_password(self, password: str) -> bool:
        if not isinstance(password, str):
            return False
        if len(password) < self._min_pw or len(password) > self._max_pw:
            return False
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        specials = "!@#$%^&*()-_=+[]{};:,.?/~"
        has_special = any(c in specials for c in password)
        return has_upper and has_lower and has_digit and has_special

    def register_user(self, username: str, password: str) -> bool:
        if not self._validate_username(username) or not self._validate_password(password):
            return False
        if username in self._db:
            return False
        try:
            salt = os.urandom(16)
            pwd_bytes = password.encode('utf-8')
            phash = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, self._iterations, dklen=self._dklen)
            self._db[username] = (salt, phash, self._iterations)
            return True
        except Exception:
            return False

    def authenticate(self, username: str, password: str) -> str:
        try:
            if not self._validate_username(username) or not isinstance(password, str) or len(password) < 1 or len(password) > self._max_pw:
                return "cant_login"
            rec = self._db.get(username)
            if rec is None:
                return "cant_login"
            salt, good_hash, iters = rec
            if not salt or not good_hash or iters < 1:
                return "cant_login"
            cand = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters, dklen=len(good_hash))
            return "success" if hmac.compare_digest(cand, good_hash) else "cant_login"
        except Exception:
            return "internal_server_error"

    # Testing helper
    def corrupt_user_record(self, username: str) -> None:
        rec = self._db.get(username)
        if rec:
            salt, phash, iters = rec
            self._db[username] = (b"", phash, iters)  # empty salt to simulate error

def generate_strong_password(length: int = 12) -> str:
    if length < 12:
        length = 12
    U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    L = "abcdefghijklmnopqrstuvwxyz"
    D = "0123456789"
    S = "!@#$%^&*()-_=+[]{};:,.?/~"
    ALL = U + L + D + S
    # Ensure complexity
    pwd = [
        secrets.choice(U),
        secrets.choice(L),
        secrets.choice(D),
        secrets.choice(S),
    ]
    for _ in range(length - 4):
        pwd.append(secrets.choice(ALL))
    # Shuffle
    for i in range(len(pwd) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pwd[i], pwd[j] = pwd[j], pwd[i]
    return "".join(pwd)

def main() -> None:
    auth = AuthService()
    user1 = "alice@example.com"
    user2 = "bob_user-1"
    pass1 = generate_strong_password(14)
    pass2 = generate_strong_password(16)

    r1 = auth.register_user(user1, pass1)
    r2 = auth.register_user(user2, pass2)

    # Test 1: correct login
    t1 = auth.authenticate(user1, pass1)
    # Test 2: wrong password (mutate first char)
    wrong = ('A' if pass1[0] != 'A' else 'B') + pass1[1:]
    t2 = auth.authenticate(user1, wrong)
    # Test 3: non-existent user
    t3 = auth.authenticate("charlie", generate_strong_password(12))
    # Test 4: invalid username format
    t4 = auth.authenticate("invalid user name with spaces", generate_strong_password(12))
    # Test 5: internal error simulation
    auth.corrupt_user_record(user2)
    t5 = auth.authenticate(user2, pass2)

    print("Test1:", t1 if r1 else "internal_server_error")
    print("Test2:", t2)
    print("Test3:", t3)
    print("Test4:", t4)
    print("Test5:", t5 if r2 else "internal_server_error")

if __name__ == "__main__":
    main()