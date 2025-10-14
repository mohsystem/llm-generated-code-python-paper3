# Chain-of-Through Process in Code (Python):
# 1) Problem understanding: Retrieve a customer by 'customerusername' from 'customer' table using command-line input; return structured object.
# 2) Security requirements: Parameterized queries, input validation, safe resource handling.
# 3) Secure coding generation: Use sqlite3 with placeholders, regex validation, minimal prints.
# 4) Code review: Ensure no SQL injection, check errors, robust handling.
# 5) Secure code output: Final secure implementation below.

import sqlite3
import re
import sys
from typing import Optional, Dict

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

def is_valid_username(username: str) -> bool:
    return isinstance(username, str) and USERNAME_REGEX.fullmatch(username) is not None

def ensure_schema_and_seed(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS customer (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customerusername TEXT UNIQUE NOT NULL,
            fullname TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    upsert = """
        INSERT INTO customer (customerusername, fullname, email)
        VALUES (?, ?, ?)
        ON CONFLICT(customerusername) DO UPDATE SET
            fullname=excluded.fullname,
            email=excluded.email
    """
    data = [
        ("alice", "Alice Anderson", "alice@example.com"),
        ("bob", "Bob Brown", "bob@example.com"),
        ("charlie", "Charlie Clark", "charlie@example.com"),
        ("dora", "Dora Dawson", "dora@example.net"),
        ("eve", "Eve Edwards", "eve@example.org"),
    ]
    conn.executemany(upsert, data)
    conn.commit()

def get_customer_by_username(conn: sqlite3.Connection, username: str) -> Optional[Dict]:
    if not is_valid_username(username):
        return None
    cur = conn.execute(
        "SELECT id, customerusername, fullname, email, COALESCE(created_at,'') "
        "FROM customer WHERE customerusername = ? LIMIT 1",
        (username,)
    )
    row = cur.fetchone()
    if row:
        return {
            "id": row[0],
            "customerusername": row[1],
            "fullname": row[2],
            "email": row[3],
            "created_at": row[4],
        }
    return None

def main():
    db_path = "customers.db"
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            ensure_schema_and_seed(conn)

            tests = []
            if len(sys.argv) >= 2 and sys.argv[1]:
                tests.append(sys.argv[1])
            defaults = ["alice", "bob", "charlie", "not_exist_user_123", "eve"]
            for d in defaults:
                if len(tests) >= 5:
                    break
                if d not in tests:
                    tests.append(d)
            while len(tests) < 5:
                tests.append("dora")
            tests = tests[:5]

            for username in tests:
                result = get_customer_by_username(conn, username)
                if result is None:
                    print(f'{{"customerusername":"{username}","result":"not_found_or_invalid"}}')
                else:
                    # Simple JSON-like output without importing json for minimal footprint
                    print("{" +
                          f"\"id\":{result['id']}," +
                          f"\"customerusername\":\"{result['customerusername']}\"," +
                          f"\"fullname\":\"{result['fullname']}\"," +
                          f"\"email\":\"{result['email']}\"," +
                          f"\"created_at\":\"{result['created_at']}\"" +
                          "}")
    except Exception:
        print('{"error":"database_error"}')

if __name__ == "__main__":
    main()