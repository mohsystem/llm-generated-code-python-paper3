# Chain-of-Through secure solution in Python (Single-file).
# Steps 1-5:
# 1) Understand problem: connect to SQL DB (SQLite in-memory), query by username, return user info dict or None.
# 2) Security: use parameterized queries, avoid exposing internals, ensure proper resource handling.
# 3) Implement using sqlite3 with placeholders.
# 4) Review: no string concatenation in SQL, all cursors/connections managed, safe prints.
# 5) Final secure code below.

import sqlite3
from typing import Optional, Dict

def connect(db_url: str) -> sqlite3.Connection:
    # SQLite in-memory database for demonstration (no credentials).
    # isolation_level=None enables autocommit if needed; we can manage transactions default.
    return sqlite3.connect(db_url)

def seed_test_data(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
        insert_sql = "INSERT INTO users (username, full_name, email, role) VALUES (?, ?, ?, ?)"
        # Use parameterized inserts to maintain security discipline consistently
        users = [
            ("alice", "Alice Johnson", "alice@example.com", "user"),
            ("bob", "Bob Smith", "bob@example.com", "user"),
            ("charlie", "Charlie Rose", "charlie@example.com", "manager"),
            ("admin", "System Admin", "admin@example.com", "admin"),
            ("eve", "Eve Adams", "eve@example.com", "auditor"),
        ]
        conn.executemany(insert_sql, users)

def get_user_info(conn: sqlite3.Connection, username: str) -> Optional[Dict[str, str]]:
    if username is None:
        return None
    sql = "SELECT username, full_name, email, role FROM users WHERE username = ?"
    # Parameterized query prevents SQL injection
    cur = conn.execute(sql, (username,))
    row = cur.fetchone()
    cur.close()
    if row:
        return {
            "username": row[0],
            "full_name": row[1],
            "email": row[2],
            "role": row[3],
        }
    return None

if __name__ == "__main__":
    try:
        conn = connect(":memory:")
        seed_test_data(conn)
        test_usernames = [
            "alice",
            "charlie",
            "nonexistent",
            "admin' OR '1'='1",
            "admin",
        ]
        for uname in test_usernames:
            try:
                user = get_user_info(conn, uname)
                print(f"Query username: {uname} -> {('Not found' if user is None else user)}")
            except Exception:
                print(f"Error querying for username: {uname}")
    except Exception:
        print("Database error occurred.")
    finally:
        try:
            conn.close()
        except Exception:
            pass