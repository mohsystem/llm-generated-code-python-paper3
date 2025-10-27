import sqlite3

def connect(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect(db_path)

def check_username_exists(conn: sqlite3.Connection, username: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ? LIMIT 1", (username,))
    row = cur.fetchone()
    cur.close()
    return row is not None

def setup_database(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY)")
    cur.executemany("INSERT OR IGNORE INTO users (username) VALUES (?)",
                    [("alice",), ("bob",), ("charlie",)])
    conn.commit()
    cur.close()

if __name__ == "__main__":
    conn = connect(":memory:")
    setup_database(conn)
    tests = ["alice", "bob", "charlie", "dave", "eve"]  # 5 test cases
    for user in tests:
        print(f"{user} -> {check_username_exists(conn, user)}")
    conn.close()