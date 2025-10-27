import sqlite3
import re
from flask import Flask, request, jsonify

USER_PATTERN = re.compile(r'^[A-Za-z0-9_]{1,32}$')

def is_moderator(conn, username):
    # Accepts input as parameters and returns output
    if username is None or not USER_PATTERN.match(username):
        return False
    cur = conn.cursor()
    cur.execute("SELECT is_moderator FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return bool(row[0]) if row else False

def create_app(conn):
    app = Flask(__name__)

    @app.get("/is_moderator")
    def route_is_moderator():
        user = request.args.get("user", "", type=str)
        try:
            result = is_moderator(conn, user)
            return jsonify({"isModerator": bool(result)}), 200
        except Exception:
            # Avoid leaking internal errors
            return jsonify({"isModerator": False}), 500

    return app

def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            is_moderator INTEGER NOT NULL CHECK(is_moderator IN (0,1))
        )
    """)
    conn.executemany("INSERT OR REPLACE INTO users(username, is_moderator) VALUES(?,?)", [
        ("alice", 1),
        ("bob", 0),
        ("charlie", 0),
        ("admin_1", 1),
    ])
    conn.commit()

if __name__ == "__main__":
    # In-memory shared DB for demonstration
    conn = sqlite3.connect("file:memdb_py?mode=memory&cache=shared", uri=True, check_same_thread=False)
    init_db(conn)
    app = create_app(conn)

    # 5 test cases using Flask test client
    with app.test_client() as client:
        for user in ["alice", "bob", "charlie", "admin_1", "unknown_user"]:
            resp = client.get("/is_moderator", query_string={"user": user})
            print(f"{user} -> {resp.get_data(as_text=True)}")