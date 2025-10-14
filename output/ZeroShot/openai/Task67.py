import os
import re
import sqlite3
from typing import Optional, Dict, Any

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

def is_valid_username(username: str) -> bool:
    return isinstance(username, str) and bool(USERNAME_REGEX.match(username))

def get_connection_or_init_sample() -> sqlite3.Connection:
    db_path = os.environ.get("DB_PATH")
    if db_path:
        conn = sqlite3.connect(db_path, timeout=5, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES)
    else:
        conn = sqlite3.connect(":memory:", timeout=5, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES)
        init_schema_and_sample_data(conn)
    conn.row_factory = sqlite3.Row
    return conn

def init_schema_and_sample_data(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS customer (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    data = [
        ("alice", "Alice Johnson", "alice@example.com", "2023-01-10T09:15:00Z"),
        ("bob", "Bob Smith", "bob@example.com", "2023-02-12T10:20:00Z"),
        ("carol", "Carol White", "carol@example.com", "2023-03-15T11:25:00Z"),
        ("dave", "Dave Brown", "dave@example.com", "2023-04-18T12:30:00Z"),
        ("eve", "Eve Black", "eve@example.com", "2023-05-20T13:35:00Z"),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO customer(username, full_name, email, created_at) VALUES (?,?,?,?)",
        data
    )

def get_customer_by_username(conn: sqlite3.Connection, customer_username: str) -> Optional[Dict[str, Any]]:
    if not is_valid_username(customer_username):
        return None
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, username, full_name, email, created_at FROM customer WHERE username = ?",
            (customer_username,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "full_name": row["full_name"],
            "email": row["email"],
            "created_at": row["created_at"],
        }
    finally:
        cur.close()

if __name__ == "__main__":
    import sys
    conn = get_connection_or_init_sample()
    try:
        if len(sys.argv) > 1:
            username = sys.argv[1]
            customer = get_customer_by_username(conn, username)
            if customer:
                print(customer)
            else:
                print(f"No customer found for username: {username}")
        else:
            tests = ["alice", "bob", "carol", "dave", "mallory"]
            for t in tests:
                customer = get_customer_by_username(conn, t)
                if customer:
                    print(customer)
                else:
                    print(f"No customer found for username: {t}")
    finally:
        conn.close()