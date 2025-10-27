import sqlite3

def user_exists(conn: sqlite3.Connection, username: str) -> bool:
    if conn is None or username is None:
        return False
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username = ? LIMIT 1", (username,))
    row = cur.fetchone()
    return row is not None

if __name__ == "__main__":
    # In-memory SQLite database
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (username TEXT PRIMARY KEY)")
    cur.executemany("INSERT INTO users(username) VALUES(?)", [("alice",), ("bob",), ("carol",)])
    conn.commit()

    tests = ["alice", "bob", "dave", "", "Carol"]  # 5 test cases
    for t in tests:
        print(f"user_exists('{t}') = {user_exists(conn, t)}")

    conn.close()