import sqlite3
import json
from typing import Optional

def get_user_info(conn: sqlite3.Connection, username: str) -> str:
    if conn is None or username is None:
        return "NOT_FOUND"
    conn.execute("PRAGMA busy_timeout = 5000")
    sql = "SELECT username, full_name, email, created_at FROM users WHERE username = ?"
    # Using parameterized query to prevent SQL injection
    cur = conn.execute(sql, (username,))
    row = cur.fetchone()
    if row:
        result = {
            "username": row[0],
            "full_name": row[1],
            "email": row[2],
            "created_at": row[3],
        }
        return json.dumps(result, separators=(",", ":"), ensure_ascii=False)
    return "NOT_FOUND"

def _seed(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    data = [
        ("alice", "Alice Anderson", "alice@example.com", "2023-01-01T00:00:00Z"),
        ("bob", "Bob Brown", "bob@example.com", "2023-02-02T00:00:00Z"),
        ("carol", "Carol Clark", "carol@example.com", "2023-03-03T00:00:00Z"),
        ("dave", "Dave Davis", "dave@example.com", "2023-04-04T00:00:00Z"),
    ]
    conn.executemany(
        "INSERT INTO users (username, full_name, email, created_at) VALUES (?, ?, ?, ?)",
        data
    )
    conn.commit()

def main():
    # In-memory SQLite for demo purposes
    with sqlite3.connect(":memory:", isolation_level=None) as conn:
        _seed(conn)
        tests = ["alice", "bob", "doesnotexist", "carol", "alice' OR '1'='1"]
        for u in tests:
            try:
                result = get_user_info(conn, u)
                print(f"Query for '{u}': {result}")
            except sqlite3.Error as e:
                print(f"Error querying for '{u}': {e}")

if __name__ == "__main__":
    main()