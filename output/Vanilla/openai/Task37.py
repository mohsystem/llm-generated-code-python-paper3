import sqlite3
import json

def init_database(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL
        )
    """)
    users = [
        (1, "alice", "Alice Wonderland", "alice@example.com"),
        (2, "bob", "Bob Builder", "bob@builder.com"),
        (3, "carol", "Carol Singer", "carol@songs.org"),
        (4, "dave", "Dave Grohl", "dave@foofighters.com"),
    ]
    cur.executemany("INSERT OR IGNORE INTO users (id, username, full_name, email) VALUES (?, ?, ?, ?)", users)
    conn.commit()

def get_user_by_username(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT id, username, full_name, email FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if row:
        user = {
            "id": row[0],
            "username": row[1],
            "full_name": row[2],
            "email": row[3]
        }
        return json.dumps(user)
    return None

if __name__ == "__main__":
    conn = sqlite3.connect(":memory:")
    init_database(conn)
    tests = ["alice", "bob", "carol", "dave", "nonexistent"]
    for t in tests:
        print(f"Query for '{t}': {get_user_by_username(conn, t)}")