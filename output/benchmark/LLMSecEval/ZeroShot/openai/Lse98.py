import sqlite3
import secrets
import hashlib
import re

ITERATIONS = 200_000
SALT_LEN = 16
HASH_LEN = 32  # 256-bit

def is_valid_username(u: str) -> bool:
    if not isinstance(u, str):
        return False
    if len(u) < 3 or len(u) > 32:
        return False
    return re.fullmatch(r'[A-Za-z0-9_.-]+', u) is not None

def is_strong_password(p: str) -> bool:
    if not isinstance(p, str) or len(p) < 8:
        return False
    has_lower = any(c.islower() for c in p)
    has_upper = any(c.isupper() for c in p)
    has_digit = any(c.isdigit() for c in p)
    has_special = any(not c.isalnum() for c in p)
    return has_lower and has_upper and has_digit and has_special

def to_hex(b: bytes) -> str:
    return b.hex()

def register_user(conn: sqlite3.Connection, username: str, password: str) -> bool:
    if conn is None or username is None or password is None:
        return False
    if not is_valid_username(username) or not is_strong_password(password):
        return False
    try:
        salt = secrets.token_bytes(SALT_LEN)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, dklen=HASH_LEN)
        with conn:
            conn.execute(
                "INSERT INTO users(username, password_hash, salt, iterations) VALUES (?, ?, ?, ?)",
                (username, to_hex(dk), to_hex(salt), ITERATIONS)
            )
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception:
        return False

def main():
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            iterations INTEGER NOT NULL
        )
    """)
    tests = [
        ("alice", "Str0ng!Pwd1"),
        ("bob", "weak"),
        ("charlie", "Anoth3r$trongPass"),
        ("bad user", "GoodPass1!"),
        ("alice", "Another$tr0ng1")
    ]
    for u, p in tests:
        ok = register_user(conn, u, p)
        print(f"Register {u}: {ok}")
    for row in conn.execute("SELECT username, iterations FROM users ORDER BY id"):
        print(f"DB -> {row[0]} iter={row[1]}")
    conn.close()

if __name__ == "__main__":
    main()