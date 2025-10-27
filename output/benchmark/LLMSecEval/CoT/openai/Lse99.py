import os
import re
import sqlite3
import hashlib
import base64
from typing import Optional

USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_.-]{3,64}$')

def is_valid_username(username: str) -> bool:
    return isinstance(username, str) and USERNAME_PATTERN.fullmatch(username) is not None

def is_valid_password(password: str) -> bool:
    return isinstance(password, str) and 8 <= len(password) <= 128

def hash_password(password: str, iterations: int = 150_000, salt_len: int = 16, dk_len: int = 32) -> str:
    if not is_valid_password(password):
        raise ValueError("Invalid password")
    salt = os.urandom(salt_len)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=dk_len)
    return f"PBKDF2${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def insert_user(db_path: str, username: str, password: str) -> bool:
    if not is_valid_username(username):
        return False
    if not is_valid_password(password):
        return False

    pwd_hash = hash_password(password)

    con: Optional[sqlite3.Connection] = None
    try:
        con = sqlite3.connect(db_path, isolation_level="EXCLUSIVE")
        con.execute("PRAGMA foreign_keys = ON;")
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)
        con.execute("INSERT INTO users(username, password_hash) VALUES (?, ?)", (username, pwd_hash))
        con.commit()
        return True
    except sqlite3.IntegrityError:
        if con:
            con.rollback()
        return False
    finally:
        if con:
            con.close()