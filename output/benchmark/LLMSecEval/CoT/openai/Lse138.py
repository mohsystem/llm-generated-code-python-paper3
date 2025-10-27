import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# Connect to the database and initialize schema/data
def connect_and_init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, is_moderator INTEGER)")
    cur.executemany(
        "INSERT INTO users (id, username, is_moderator) VALUES (?, ?, ?)",
        [
            (1, 'alice', 1),
            (2, 'bob', 0),
            (3, 'carol', 1),
            (4, 'dave', 0),
            (5, 'eve', 0),
        ],
    )
    conn.commit()
    return conn

# Execute a query to check if the user is a moderator
def is_moderator(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT is_moderator FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    return bool(row[0]) if row else False

# Define a route and handler for the web app
def start_server(conn, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path != "/isModerator":
                self.send_response(404)
                self.end_headers()
                return
            qs = parse_qs(parsed.query)
            uid_vals = qs.get("userId", [])
            result = False
            if uid_vals:
                try:
                    uid = int(uid_vals[0])
                    result = is_moderator(conn, uid)
                except Exception:
                    result = False
            body = str(result).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    server = HTTPServer(("0.0.0.0", port), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

if __name__ == "__main__":
    conn = connect_and_init_db()
    server = start_server(conn, 8081)
    print("Python server started on http://localhost:8081/isModerator?userId={id}")

    # 5 test cases
    test_ids = [1, 2, 3, 4, 999]
    for uid in test_ids:
        print(f"Test userId={uid} -> isModerator={is_moderator(conn, uid)}")

    import time
    time.sleep(3)
    server.shutdown()
    conn.close()