import os
import sqlite3
import base64
import secrets
import hashlib
import re
from datetime import datetime

PBKDF2_ITERS = 210_000
SALT_LEN = 16
DK_LEN = 32
USERNAME_RX = re.compile(r"^[A-Za-z0-9_]{3,32}$")

def is_valid_username(username: str) -> bool:
    if username is None:
        return False
    return bool(USERNAME_RX.fullmatch(username))

def is_strong_password(password: str) -> bool:
    if password is None or len(password) < 12:
        return False
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_lower and has_upper and has_digit and has_special

def hash_password(password: str):
    salt = secrets.token_bytes(SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERS, dklen=DK_LEN)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(dk).decode("ascii")
    # Python strings are immutable; avoid keeping password longer than needed by not storing it.
    return (salt_b64, hash_b64, PBKDF2_ITERS)

def ensure_schema(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            iterations INTEGER NOT NULL,
            salt_b64 TEXT NOT NULL,
            hash_b64 TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()

def insert_user(db_path: str, username: str, password: str) -> bool:
    if not is_valid_username(username):
        return False
    if not is_strong_password(password):
        return False

    conn = sqlite3.connect(db_path, isolation_level="DEFERRED")
    try:
        ensure_schema(conn)
        salt_b64, hash_b64, iters = hash_password(password)
        created_at = datetime.utcnow().isoformat() + "Z"
        try:
            conn.execute(
                "INSERT INTO users (username, iterations, salt_b64, hash_b64, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, iters, salt_b64, hash_b64, created_at)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Likely duplicate username
            conn.rollback()
            return False
    finally:
        conn.close()

def main():
    db = "users_py.db"
    if os.path.exists(db):
        os.remove(db)

    tests = [
        ("alice_01", "StrongPass!234"),
        ("bob_02", "Another$trongP4ss"),
        ("alice_01", "DupUserGoodP@ss1"),  # duplicate username
        ("ab", "ValidButUserTooShort1!"),
        ("charlie_03", "weakpass"),  # weak password
    ]

    for i, (u, p) in enumerate(tests, 1):
        ok = insert_user(db, u, p)
        print(f"Test {i} insert({u}): {'OK' if ok else 'FAIL'}")

    # Show number of records stored
    conn = sqlite3.connect(db)
    try:
        cur = conn.execute("SELECT COUNT(*) FROM users")
        count = cur.fetchone()[0]
        print(f"Total records in DB: {count}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()