import sqlite3
import re
from typing import List, Dict, Any

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{1,30}$")

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 1 or len(username) > 30:
        return False
    return USERNAME_REGEX.fullmatch(username) is not None

def setup_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY, "
            "username TEXT NOT NULL UNIQUE, "
            "email TEXT NOT NULL, "
            "full_name TEXT NOT NULL)"
        )
        data = [
            (1, "alice", "alice@example.com", "Alice Allison"),
            (2, "bob", "bob@example.com", "Bob Robertson"),
            (3, "carol", "carol@example.com", "Carol Carver"),
            (4, "dave_123", "dave@example.com", "Dave Davidson"),
            (5, "eve", "eve@example.com", "Eve Everson"),
        ]
        for row in data:
            try:
                conn.execute(
                    "INSERT INTO users (id, username, email, full_name) VALUES (?, ?, ?, ?)", row
                )
            except sqlite3.IntegrityError:
                pass

def query_user(conn: sqlite3.Connection, username: str) -> List[Dict[str, Any]]:
    if not is_valid_username(username):
        raise ValueError("Invalid username. Only alphanumeric and underscore allowed, length 1-30.")
    rows = conn.execute(
        "SELECT id, username, email, full_name FROM users WHERE username = ?", (username,)
    ).fetchall()
    results: List[Dict[str, Any]] = []
    for r in rows:
        results.append(
            {
                "id": int(r[0]),
                "username": str(r[1]),
                "email": str(r[2]),
                "full_name": str(r[3]),
            }
        )
    return results

def main() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    try:
        setup_db(conn)
        tests = [
            "alice",
            "bob",
            "carol",
            "nonexistent",
            "alice' OR '1'='1",  # should be rejected
        ]
        for t in tests:
            try:
                res = query_user(conn, t)
                print(f"Query for '{t}' -> {res}")
            except ValueError as ve:
                print(f"Query for '{t}' rejected: {ve}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()