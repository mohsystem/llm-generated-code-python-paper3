# Chain-of-Through in comments:
# 1) Problem understanding: Register a user by hashing password and inserting into a database.
# 2) Security requirements: Validate input, use strong KDF (PBKDF2-HMAC-SHA256 with high iterations and random salt), parameterized SQL.
# 3) Secure coding: Use sqlite3 with prepared statements, os.urandom, no plaintext storage.
# 4) Code review: Ensure uniqueness, safe encodings, no secret prints.
# 5) Secure code output: Final implementation below.

import os
import sqlite3
import hashlib
import hmac
import binascii
import re

ITERATIONS = 200_000
SALT_LEN = 16

def _valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 64:
        return False
    return re.fullmatch(r"[A-Za-z0-9_.-]+", username) is not None

def _valid_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) < 8 or len(password) > 1024:
        return False
    hasU = any(c.isupper() for c in password)
    hasL = any(c.islower() for c in password)
    hasD = any(c.isdigit() for c in password)
    hasS = any(not c.isalnum() for c in password)
    return hasU and hasL and hasD and hasS

def register_user(conn: sqlite3.Connection, username: str, password: str) -> bool:
    if not _valid_username(username) or not _valid_password(password):
        return False
    salt = os.urandom(SALT_LEN)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, dklen=32)
    try:
        with conn:
            conn.execute(
                "INSERT INTO users(username, salt, hash, iterations) VALUES(?, ?, ?, ?)",
                (username, salt, dk, ITERATIONS)
            )
        return True
    except sqlite3.IntegrityError:
        return False

def _init_db(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt BLOB NOT NULL,
            hash BLOB NOT NULL,
            iterations INTEGER NOT NULL
        )
    """)

def _hex(b: bytes) -> str:
    return binascii.hexlify(b).decode('ascii')

if __name__ == "__main__":
    # Setup in-memory DB
    conn = sqlite3.connect(":memory:", isolation_level=None)
    _init_db(conn)

    # 5 test cases
    print("T1 alice:", register_user(conn, "alice", "StrongP@ssw0rd!"))
    print("T2 bob (weak):", register_user(conn, "bob", "weak"))
    print("T3 alice duplicate:", register_user(conn, "alice", "AnotherStr0ng!"))
    print("T4 charlie:", register_user(conn, "charlie", "Cmplx#Pass123"))
    print("T5 bad username:", register_user(conn, "bad user", "G00d#Pass!"))

    # Show stored rows without exposing plaintext passwords
    for row in conn.execute("SELECT id, username, hex(salt), hex(hash), iterations FROM users ORDER BY id"):
        print(row)