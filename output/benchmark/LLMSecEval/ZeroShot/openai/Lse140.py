import sqlite3
from typing import Optional

def username_exists(db_path: str, username: Optional[str]) -> bool:
    if not db_path or not username:
        return False
    try:
        with sqlite3.connect(db_path, isolation_level=None, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cur = conn.execute("SELECT 1 FROM users WHERE username = ? LIMIT 1", (username,))
            return cur.fetchone() is not None
    except sqlite3.Error:
        # Avoid leaking DB details; return False on error
        return False

def _init_db(db_path: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL)")
        conn.executemany("INSERT OR IGNORE INTO users (username) VALUES (?)", [(u,) for u in ("alice", "bob", "eve")])
        conn.commit()

if __name__ == "__main__":
    db_path = "users_py.db"
    _init_db(db_path)
    tests = [
        "alice",
        "bob",
        "charlie",
        "",
        "Robert'); DROP TABLE users;--",
    ]
    for t in tests:
        print(f'username_exists("{t}") = {username_exists(db_path, t)}')