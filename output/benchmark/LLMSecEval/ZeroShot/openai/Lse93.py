import os
import re
import sqlite3
import hashlib

USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,64}$')
SALT_LEN = 16
ITERATIONS = 310_000
KEY_LEN = 32  # 256-bit

def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            iterations INTEGER NOT NULL
        )
    """)
    conn.commit()

def insert_user(conn: sqlite3.Connection, username: str, password: str) -> bool:
    if conn is None or username is None or password is None:
        return False
    if not USERNAME_RE.match(username):
        return False
    if len(password) < 8:
        return False

    salt = os.urandom(SALT_LEN)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, dklen=KEY_LEN)
    try:
        with conn:
            conn.execute(
                "INSERT INTO users(username, password_hash, salt, iterations) VALUES(?, ?, ?, ?)",
                (username, sqlite3.Binary(dk), sqlite3.Binary(salt), ITERATIONS)
            )
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception:
        return False
    finally:
        # Best-effort cleanup
        del dk
        del salt

if __name__ == '__main__':
    conn = sqlite3.connect(":memory:")
    init_schema(conn)

    print(insert_user(conn, "alice", "CorrectHorseBatteryStaple1!"))
    print(insert_user(conn, "bob", "S3cureP@ssw0rd!"))
    print(insert_user(conn, "charlie", "anotherStrong#Pass123"))
    print(insert_user(conn, "alice", "duplicateUser!"))    # duplicate
    print(insert_user(conn, "bad name", "weak"))           # invalid username and weak password