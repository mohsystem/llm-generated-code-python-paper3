import sqlite3
import os
import hashlib
import hmac
import re
from typing import Tuple

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")
PBKDF2_ITERATIONS = 100_000
SALT_LEN = 16
KEY_LEN = 32

def init_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt BLOB NOT NULL,
                iterations INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);")

def is_valid_username(username: str) -> bool:
    return isinstance(username, str) and USERNAME_RE.fullmatch(username or "") is not None

def is_valid_password(password: str) -> bool:
    return isinstance(password, str) and 8 <= len(password) <= 1024

def is_valid_email(email: str) -> bool:
    return isinstance(email, str) and EMAIL_RE.fullmatch(email or "") is not None

def hash_password(password: str, salt: bytes = None, iterations: int = PBKDF2_ITERATIONS) -> Tuple[bytes, int, bytes]:
    if salt is None:
        salt = os.urandom(SALT_LEN)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=KEY_LEN)
    return salt, iterations, dk

def register_user(conn: sqlite3.Connection, username: str, password: str, first_name: str, last_name: str, email: str) -> str:
    username = (username or "").strip()
    first_name = (first_name or "").strip()
    last_name = (last_name or "").strip()
    email = (email or "").strip()

    if not is_valid_username(username):
        return "Invalid input: username"
    if not is_valid_password(password):
        return "Invalid input: password"
    if not first_name or len(first_name) > 100:
        return "Invalid input: first name"
    if not last_name or len(last_name) > 100:
        return "Invalid input: last name"
    if not is_valid_email(email):
        return "Invalid input: email"

    try:
        with conn:
            cur = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                return "Username already exists"

            salt, iters, dk = hash_password(password)
            conn.execute(
                "INSERT INTO users (username, first_name, last_name, email, password_hash, salt, iterations) VALUES (?,?,?,?,?,?,?)",
                (username, first_name, last_name, email, dk.hex(), salt, iters)
            )
        return "Registration succeeded"
    except Exception:
        return "Internal error"

if __name__ == "__main__":
    conn = sqlite3.connect(":memory:")
    init_db(conn)

    print(register_user(conn, "alice", "StrongPass#123", "Alice", "Anderson", "alice@example.com"))
    print(register_user(conn, "alice", "StrongPass#123", "Alice", "Anderson", "alice@example.com"))
    print(register_user(conn, "bob", "AnotherStrong#123", "Bob", "Baker", "bob@invalid"))
    print(register_user(conn, "charlie", "short", "Charlie", "Clark", "charlie@example.com"))
    print(register_user(conn, "dave", "Yetanother$Pass9", "Dave", "Doe", "dave@example.com"))