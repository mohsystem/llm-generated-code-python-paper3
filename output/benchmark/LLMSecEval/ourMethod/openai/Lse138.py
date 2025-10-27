import os
import re
import json
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
import sqlite3
from typing import Tuple

USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
DB_LOCK = threading.Lock()
DB_CONN = None  # type: sqlite3.Connection

def init_db(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, role TEXT NOT NULL)")
    # Seed data for demo (would be external in production)
    with conn:
        conn.execute("INSERT OR REPLACE INTO users(username, role) VALUES(?,?)", ("alice", "moderator"))
        conn.execute("INSERT OR REPLACE INTO users(username, role) VALUES(?,?)", ("bob", "user"))
        conn.execute("INSERT OR REPLACE INTO users(username, role) VALUES(?,?)", ("carol", "moderator"))
        conn.execute("INSERT OR REPLACE INTO users(username, role) VALUES(?,?)", ("dave", "user"))
        conn.execute("INSERT OR REPLACE INTO users(username, role) VALUES(?,?)", ("eve", "moderator"))

def connect_db() -> sqlite3.Connection:
    # Use environment variable to choose DB path; default to in-memory
    db_path = os.environ.get("PY_DB_PATH", ":memory:")
    conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def is_valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    return bool(USERNAME_RE.fullmatch(username))

def check_is_moderator(conn: sqlite3.Connection, username: str) -> bool:
    # Prepared statement to avoid injection
    with DB_LOCK:
        cur = conn.execute("SELECT role FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    return bool(row and row[0] == "moderator")

class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if not self.path.startswith("/is_moderator"):
            self._send(404, {"error": "not found"})
            return
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=False, strict_parsing=False)
        raw_username = params.get("username", [""])[0]
        try:
            username = urllib.parse.unquote(raw_username, encoding="utf-8", errors="strict")
        except Exception:
            self._send(400, {"error": "invalid username"})
            return
        if not is_valid_username(username):
            self._send(400, {"error": "invalid username"})
            return
        ok = check_is_moderator(DB_CONN, username)
        self._send(200, {"username": username, "is_moderator": ok})

    def log_message(self, format: str, *args) -> None:
        # Reduce server logs and avoid leaking details
        return

    def _send(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def start_server(server: HTTPServer) -> None:
    server.serve_forever()

def http_get(url: str, timeout: float = 3.0) -> Tuple[int, str]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.getcode(), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body

def main() -> None:
    global DB_CONN
    DB_CONN = connect_db()
    init_db(DB_CONN)

    server = HTTPServer(("127.0.0.1", 8000), Handler)
    t = threading.Thread(target=start_server, args=(server,), daemon=True)
    t.start()

    # 5 test cases
    tests = ["alice", "bob", "carol", "dave", "unknown"]
    for u in tests:
        url = f"http://127.0.0.1:8000/is_moderator?username={urllib.parse.quote(u, safe='')}"
        code, body = http_get(url)
        print(body)

    server.shutdown()
    server.server_close()
    with DB_LOCK:
        DB_CONN.close()

if __name__ == "__main__":
    main()