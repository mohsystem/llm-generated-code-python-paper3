import sqlite3
import hashlib
import secrets
import re

class Lse99:
    ITERATIONS = 100_000
    SALT_LEN = 16
    DK_LEN = 32

    @staticmethod
    def _is_valid_username(username: str) -> bool:
        if not isinstance(username, str):
            return False
        if len(username) < 3 or len(username) > 64:
            return False
        return re.fullmatch(r"[A-Za-z0-9_.-]+", username) is not None

    @staticmethod
    def _is_valid_password(password: str) -> bool:
        if not isinstance(password, str):
            return False
        return len(password) >= 8

    @staticmethod
    def _hash_password(password: str):
        salt = secrets.token_bytes(Lse99.SALT_LEN)
        hash_bytes = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            Lse99.ITERATIONS,
            dklen=Lse99.DK_LEN,
        )
        return salt, Lse99.ITERATIONS, hash_bytes

    @staticmethod
    def register_user(conn: sqlite3.Connection, username: str, password: str) -> bool:
        if conn is None or username is None or password is None:
            return False
        if not Lse99._is_valid_username(username):
            return False
        if not Lse99._is_valid_password(password):
            return False

        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt     BLOB NOT NULL,
                iterations INTEGER NOT NULL,
                hash     BLOB NOT NULL
            )
        """)
        salt, iterations, hash_bytes = Lse99._hash_password(password)

        try:
            cur.execute(
                "INSERT INTO users (username, salt, iterations, hash) VALUES (?, ?, ?, ?)",
                (username, salt, iterations, hash_bytes)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

if __name__ == "__main__":
    conn = sqlite3.connect(":memory:")
    test_users = [
        ("alice_01", "S3cureP@ss1"),
        ("bob-02", "Another$trong2"),
        ("charlie.03", "Y3tAn0therStrong!"),
        ("diana04", "Password#WithLength123"),
        ("eve05", "Complex&Pass99"),
    ]
    for u, p in test_users:
        print("Register", u, Lse99.register_user(conn, u, p))

    # Show rows
    cur = conn.cursor()
    cur.execute("SELECT username, length(salt), iterations, length(hash) FROM users ORDER BY username")
    for row in cur.fetchall():
        print(row)

    # Duplicate test
    print("Duplicate alice_01:", Lse99.register_user(conn, "alice_01", "S3cureP@ss1"))