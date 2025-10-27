import re
import sqlite3
import secrets
import hashlib
from typing import Optional

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z '\-]{0,49}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

def is_valid_username(s: Optional[str]) -> bool:
    if s is None: return False
    v = s.strip()
    return USERNAME_RE.fullmatch(v) is not None

def is_valid_name(s: Optional[str]) -> bool:
    if s is None: return False
    v = s.strip()
    return 1 <= len(v) <= 50 and NAME_RE.fullmatch(v) is not None

def is_valid_email(s: Optional[str]) -> bool:
    if s is None: return False
    v = s.strip()
    return len(v) <= 254 and EMAIL_RE.fullmatch(v) is not None

def is_strong_password(s: Optional[str]) -> bool:
    if s is None: return False
    if len(s) < 12 or len(s) > 1024:
        return False
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_special = any(not c.isalnum() for c in s)
    return has_upper and has_lower and has_digit and has_special

def initialize_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL,
            salt BLOB NOT NULL,
            hash BLOB NOT NULL,
            iterations INTEGER NOT NULL
        )
    """)
    conn.commit()

def register_user(conn: sqlite3.Connection, username: str, password: str, first_name: str, last_name: str, email: str) -> str:
    if not is_valid_username(username):
        return "Invalid username"
    if not is_strong_password(password):
        return "Invalid password"
    if not is_valid_name(first_name):
        return "Invalid first name"
    if not is_valid_name(last_name):
        return "Invalid last name"
    if not is_valid_email(email):
        return "Invalid email"

    uname = username.strip()
    fname = first_name.strip()
    lname = last_name.strip()
    mail = email.strip()

    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ?", (uname,))
    if cur.fetchone() is not None:
        return "Username already exists"

    salt = secrets.token_bytes(16)
    iterations = 210_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)

    cur.execute(
        "INSERT INTO users (username, first_name, last_name, email, salt, hash, iterations) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (uname, fname, lname, mail, salt, dk, iterations)
    )
    conn.commit()
    return "Registration succeeded"

def main():
    conn = sqlite3.connect(":memory:")
    initialize_db(conn)

    tests = [
        ("alice.user", "Str0ng!Password", "Alice", "Smith", "alice@example.com"),
        ("alice.user", "An0ther!StrongPass", "Alice", "Smith", "alice+dup@example.com"),
        ("a", "Str0ng!Password", "A", "User", "a@ex.com"),
        ("bob-user", "weakpass", "Bob", "Jones", "bob@example.com"),
        ("charlie99", "G00d!EnoughPass", "Charlie", "Brown", "charlie.brown@example.org"),
    ]

    for i, (u, p, f, l, e) in enumerate(tests, 1):
        result = register_user(conn, u, p, f, l, e)
        print(f"Test {i}: {result}")

if __name__ == "__main__":
    main()