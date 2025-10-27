import secrets
import hashlib
import hmac
import re
from typing import Dict

SALT_LEN = 16
HASH_LEN = 32  # 256-bit
ITERATIONS = 210_000

class User:
    def __init__(self, username: str, salt: bytes, pw_hash: bytes, iterations: int) -> None:
        self.username = username
        self.salt = salt[:]
        self.pw_hash = pw_hash[:]
        self.iterations = iterations

class InMemoryDB:
    def __init__(self) -> None:
        self.users: Dict[str, User] = {}

    def add_user(self, username: str, password: str) -> None:
        if not validate_username(username):
            raise ValueError("Invalid username format")
        if not validate_password(password):
            raise ValueError("Invalid password format")
        if username in self.users:
            raise ValueError("User exists")
        salt = secrets.token_bytes(SALT_LEN)
        pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=HASH_LEN)
        self.users[username] = User(username, salt, pw_hash, ITERATIONS)

    def find_by_username(self, username: str):
        return self.users.get(username)

def validate_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 32:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9._-]+", username))

def validate_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    return 8 <= len(password) <= 128

def handle_login(db: InMemoryDB, username: str, password: str) -> str:
    try:
        if not validate_username(username) or not validate_password(password):
            return "REDIRECT:/login"
        user = db.find_by_username(username)
        if not user:
            return "REDIRECT:/login"
        computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), user.salt, user.iterations, dklen=len(user.pw_hash))
        ok = hmac.compare_digest(computed, user.pw_hash)
        return "REDIRECT:/dashboard" if ok else "REDIRECT:/login"
    except Exception:
        return "REDIRECT:/login"

if __name__ == "__main__":
    db = InMemoryDB()
    db.add_user("alice", "CorrectHorse1!")
    db.add_user("bob", "S3cureP@ssw0rd")

    tests = [
        ("alice", "CorrectHorse1!"),  # correct
        ("alice", "wrongpass"),       # wrong password
        ("charlie", "NoSuchUser1!"),  # unknown user
        ("x", "SomeValid1!"),         # invalid username
        ("bob", "short"),             # invalid password
    ]

    for i, (u, p) in enumerate(tests, 1):
        print(f"Test {i}: {handle_login(db, u, p)}")