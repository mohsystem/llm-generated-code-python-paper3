import sqlite3
import os
import re
import hashlib
import hmac

DB_PATH = "task46_py.db"
ITERATIONS = 120000
SALT_LENGTH = 16
KEY_LENGTH = 32
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")

def init_db(db_path: str) -> bool:
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password_hash BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    iterations INTEGER NOT NULL
                )
            """)
        return True
    except sqlite3.Error:
        return False

def _valid_name(name: str) -> bool:
    if not isinstance(name, str):
        return False
    n = name.strip()
    return len(n) > 0 and len(n) <= 100

def _valid_email(email: str) -> bool:
    if not isinstance(email, str):
        return False
    e = email.strip().lower()
    return EMAIL_REGEX.match(e) is not None

def _valid_password(password: str) -> bool:
    if not isinstance(password, str) or len(password) < 8:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    specials = set("!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~\\")
    has_special = any(c in specials for c in password)
    return has_upper and has_lower and has_digit and has_special

def register_user(db_path: str, name: str, email: str, password: str) -> bool:
    if not (_valid_name(name) and _valid_email(email) and _valid_password(password)):
        return False
    salt = os.urandom(SALT_LENGTH)
    try:
        pwd_bytes = password.encode('utf-8')
        dk = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, ITERATIONS, dklen=KEY_LENGTH)
        # Best-effort wipe
        del pwd_bytes
    except Exception:
        return False

    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute(
                "INSERT INTO users(name, email, password_hash, salt, iterations) VALUES(?,?,?,?,?)",
                (name.strip(), email.strip().lower(), sqlite3.Binary(dk), sqlite3.Binary(salt), ITERATIONS)
            )
        return True
    except sqlite3.IntegrityError:
        return False
    except sqlite3.Error:
        return False
    finally:
        # Wipe sensitive materials
        try:
            # Overwrite bytearrays for security; here dk and salt are bytes (immutable),
            # convert to bytearray for wipe attempt
            ba = bytearray(dk)
            for i in range(len(ba)):
                ba[i] = 0
        except Exception:
            pass

if __name__ == "__main__":
    init_db(DB_PATH)
    print(register_user(DB_PATH, "Alice Smith", "alice@example.com", "Str0ng!Pass1"))
    print(register_user(DB_PATH, "Bob Johnson", "bob@example.com", "An0ther#Good2"))
    print(register_user(DB_PATH, "Charlie", "bad-email", "Weak"))  # invalid
    print(register_user(DB_PATH, "Dana White", "dana.white@example.org", "Secur3$Pass4"))
    print(register_user(DB_PATH, "Eve Adams", "alice@example.com", "Str0ng!Pass1"))  # duplicate