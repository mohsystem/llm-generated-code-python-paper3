import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from urllib.parse import urlparse, parse_qs

def connect_db():
    # Connect to an in-memory SQLite database
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (user_id TEXT PRIMARY KEY, is_moderator INTEGER NOT NULL)")
    return conn

def seed_db(conn, data):
    conn.executemany("INSERT INTO users(user_id, is_moderator) VALUES(?, ?)", data)
    conn.commit()

def is_moderator(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT is_moderator FROM users WHERE user_id = ?", (str(user_id),))
    row = cur.fetchone()
    return bool(row[0]) if row is not None else False

def handle_route(conn, user_id):
    return "true" if is_moderator(conn, user_id) else "false"

class AppHandler(BaseHTTPRequestHandler):
    db_conn = None

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/is_moderator":
            self.send_response(404)
            self.end_headers()
            return
        params = parse_qs(parsed.query or "")
        user_id = params.get("userId", [None])[0]
        result = handle_route(self.db_conn, user_id)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(result.encode("utf-8"))

def start_server(conn, host="127.0.0.1", port=8082):
    AppHandler.db_conn = conn
    server = HTTPServer((host, port), AppHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

if __name__ == "__main__":
    conn = connect_db()
    seed_db(conn, [
        ("1", 1),
        ("2", 0),
        ("3", 1),
        ("4", 0),
        ("5", 1),
    ])
    srv = start_server(conn)

    # 5 test cases by direct function invocation
    print(handle_route(conn, "1"))  # expected: true
    print(handle_route(conn, "2"))  # expected: false
    print(handle_route(conn, "3"))  # expected: true
    print(handle_route(conn, "4"))  # expected: false
    print(handle_route(conn, "999"))  # expected: false

    srv.shutdown()