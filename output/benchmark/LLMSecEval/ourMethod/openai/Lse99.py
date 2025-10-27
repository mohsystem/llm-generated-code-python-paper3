import sqlite3
import secrets
import hashlib
import re
from typing import Optional

MIN_PW_LEN = 12
MAX_PW_LEN = 128
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,50}$")
PBKDF2_ITERS = 210_000
SALT_LEN = 16
KEY_LEN = 32  # 256-bit

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    return bool(USERNAME_RE.fullmatch(username))

def is_valid_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) < MIN_PW_LEN or len(password) > MAX_PW_LEN:
        return False
    lower = any(c.islower() for c in password)
    upper = any(c.isupper() for c in password)
    digit = any(c.isdigit() for c in password)
    other = any(not c.isalnum() for c in password)
    return lower and upper and digit and other

def create_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            salt BLOB NOT NULL,
            hash BLOB NOT NULL,
            iterations INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn

def register_user(conn: sqlite3.Connection, username: str, password: str) -> bool:
    if not is_valid_username(username) or not is_valid_password(password):
        return False
    salt = secrets.token_bytes(SALT_LEN)
    pw_bytes = password.encode("utf-8")
    try:
        pw_hash = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, PBKDF2_ITERS, dklen=KEY_LEN)
        with conn:
            conn.execute(
                "INSERT INTO users(username, salt, hash, iterations) VALUES (?, ?, ?, ?)",
                (username, salt, pw_hash, PBKDF2_ITERS),
            )
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        # Best-effort cleanup of sensitive variables
        del pw_bytes

def main():
    conn = create_db()
    tests = [
        ("alice_01", "StrongPass!234"),
        ("bob", "Another$trongP4ss"),
        ("alice_01", "DuplicateUser!234"),  # duplicate username
        ("x", "TooShort!1"),                # invalid username and password
        ("charlie_3", "Val1d#PasswordThing"),
    ]
    for u, p in tests:
        ok = register_user(conn, u, p)
        print(f"Register({u}): {'ok' if ok else 'failed'}")
    cur = conn.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    print(f"Total users stored: {count}")

if __name__ == "__main__":
    main()