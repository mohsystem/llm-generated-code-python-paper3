import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from urllib import request

# Simple SQLite database wrapper
class DB:
    def __init__(self, path=":memory:"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT, age INTEGER)")
        self.conn.commit()
        self.lock = threading.Lock()

    def add_user(self, name, email, age):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("INSERT INTO users(name,email,age) VALUES(?,?,?)", (name, email, age))
            self.conn.commit()
            return cur.lastrowid

    def get_all_users_json(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id, name, email, age FROM users ORDER BY id")
            rows = cur.fetchall()
        users = [{"id": r[0], "name": r[1], "email": r[2], "age": r[3]} for r in rows]
        return json.dumps(users)

DB_INSTANCE = DB()

# Public API functions
def add_user(name: str, email: str, age: int) -> int:
    return DB_INSTANCE.add_user(name, email, age)

def get_all_users_json() -> str:
    return DB_INSTANCE.get_all_users_json()

class UsersHandler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, data: dict | list | str):
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        if isinstance(data, (dict, list)):
            self.wfile.write(json.dumps(data).encode("utf-8"))
        else:
            self.wfile.write(data.encode("utf-8"))

    def do_POST(self):
        if self.path != "/users":
            self._send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        try:
            payload = json.loads(body)
            name = payload.get("name")
            email = payload.get("email")
            age = payload.get("age")
            if not isinstance(name, str) or not isinstance(email, str) or not isinstance(age, int):
                self._send_json(400, {"error": "invalid input"})
                return
            user_id = add_user(name, email, age)
            self._send_json(200, {"status": "ok", "id": user_id})
        except Exception:
            self._send_json(400, {"error": "invalid json"})

    def do_GET(self):
        if self.path != "/users":
            self._send_json(404, {"error": "not found"})
            return
        self._send_json(200, json.loads(get_all_users_json()))

def start_server(port: int) -> HTTPServer:
    server = HTTPServer(("localhost", port), UsersHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

def http_post(url: str, data_json: str) -> str:
    req = request.Request(url, data=data_json.encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
    with request.urlopen(req) as resp:
        return resp.read().decode("utf-8")

def http_get(url: str) -> str:
    with request.urlopen(url) as resp:
        return resp.read().decode("utf-8")

if __name__ == "__main__":
    port = 8082
    srv = start_server(port)

    payloads = [
        {"name": "Alice", "email": "alice@example.com", "age": 30},
        {"name": "Bob", "email": "bob@example.com", "age": 25},
        {"name": "Carol", "email": "carol@example.com", "age": 28},
        {"name": "Dave", "email": "dave@example.com", "age": 40},
        {"name": "Eve", "email": "eve@example.com", "age": 22},
    ]
    base = f"http://localhost:{port}/users"
    for p in payloads:
        print(http_post(base, json.dumps(p)))
    print(http_get(base))

    srv.shutdown()