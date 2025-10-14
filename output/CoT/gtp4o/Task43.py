import base64
import hashlib
import hmac
import http.client
import json
import secrets
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

class Task43:
    class UserStore:
        def __init__(self):
            self.users = {}
            self.iterations = 150_000

        def add_user(self, username: str, password: str):
            if username is None or password is None:
                raise ValueError("Nulls not allowed")
            salt = secrets.token_bytes(16)
            dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self.iterations, dklen=32)
            self.users[username] = (salt, dk, self.iterations)

        def verify(self, username: str, password: str) -> bool:
            entry = self.users.get(username)
            if not entry:
                # fake compute to mitigate timing differences
                fake_salt = secrets.token_bytes(16)
                hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), fake_salt, self.iterations, dklen=32)
                return False
            salt, stored, iters = entry
            calc = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters, dklen=len(stored))
            return hmac.compare_digest(stored, calc)

    class SessionManager:
        def __init__(self):
            self.sessions = {}
            self.ttl = 30 * 60  # seconds

        def create_session(self, user: str) -> str:
            sid = secrets.token_urlsafe(32)
            self.sessions[sid] = (user, Task43.now() + self.ttl)
            return sid

        def validate(self, sid: str):
            if not sid:
                return None
            val = self.sessions.get(sid)
            if not val:
                return None
            user, exp = val
            if Task43.now() > exp:
                self.sessions.pop(sid, None)
                return None
            return user

        def terminate(self, sid: str) -> bool:
            if not sid:
                return False
            return self.sessions.pop(sid, None) is not None

    @staticmethod
    def now():
        import time
        return int(time.time())

    class _Handler(BaseHTTPRequestHandler):
        def __init__(self, *args, app=None, **kwargs):
            self.app = app
            super().__init__(*args, **kwargs)

        def log_message(self, format, *args):
            return  # silence

        def do_POST(self):
            if self.path == "/login":
                self.handle_login()
            elif self.path == "/logout":
                self.handle_logout()
            else:
                self.send_error_json(404, "Not Found")

        def do_GET(self):
            if self.path == "/me":
                self.handle_me()
            else:
                self.send_error_json(404, "Not Found")

        def read_json(self):
            ctype = self.headers.get('Content-Type', '')
            if not ctype.lower().startswith('application/json'):
                self.send_error_json(400, "Invalid Content-Type")
                return None
            try:
                length = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(length) if length > 0 else b''
                return json.loads(body.decode('utf-8') or "{}")
            except Exception:
                self.send_error_json(400, "Invalid JSON")
                return None

        def set_common_headers(self):
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')

        def build_cookie(self, sid: str, expire: bool) -> str:
            parts = [f"SID={sid}", "Path=/", "HttpOnly", "SameSite=Strict", "Secure"]
            if expire:
                parts.append("Max-Age=0")
            else:
                parts.append("Max-Age=1800")
            return "; ".join(parts)

        def get_cookie(self, name: str):
            cookie = self.headers.get('Cookie')
            if not cookie:
                return None
            for part in cookie.split(';'):
                if '=' in part:
                    k, v = part.strip().split('=', 1)
                    if k == name:
                        return v
            return None

        def send_json(self, code: int, obj: dict):
            body = json.dumps(obj).encode('utf-8')
            self.send_response(code)
            self.set_common_headers()
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_error_json(self, code: int, msg: str):
            self.send_json(code, {"error": msg})

        def handle_login(self):
            data = self.read_json()
            if data is None:
                return
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                self.send_error_json(400, "Missing fields")
                return
            if not self.app.user_store.verify(username, password):
                self.send_error_json(401, "Invalid credentials")
                return
            sid = self.app.session_manager.create_session(username)
            self.send_response(200)
            self.set_common_headers()
            self.send_header('Set-Cookie', self.build_cookie(sid, False))
            body = json.dumps({"status": "ok"}).encode('utf-8')
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def handle_me(self):
            sid = self.get_cookie('SID')
            user = self.app.session_manager.validate(sid)
            if not user:
                self.send_error_json(401, "Not authenticated")
                return
            self.send_json(200, {"user": user})

        def handle_logout(self):
            sid = self.get_cookie('SID')
            if sid:
                self.app.session_manager.terminate(sid)
            self.send_response(200)
            self.set_common_headers()
            self.send_header('Set-Cookie', self.build_cookie("deleted", True))
            body = json.dumps({"status": "logged_out"}).encode('utf-8')
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def __init__(self):
        self.user_store = Task43.UserStore()
        self.user_store.add_user("alice", "p@ssw0rd-Example!")
        self.session_manager = Task43.SessionManager()
        self._server = None
        self.port = None

    def _make_handler(self):
        app = self
        def handler(*args, **kwargs):
            Task43._Handler(*args, app=app, **kwargs)
        return handler

    def start(self):
        # Bind to an ephemeral port on localhost
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        host, port = sock.getsockname()
        sock.close()
        self.port = port
        self._server = HTTPServer(("127.0.0.1", self.port), self._make_handler())
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()

if __name__ == "__main__":
    app = Task43()
    app.start()
    base = f"127.0.0.1:{app.port}"

    # Helper HTTP client functions
    def post_json(path, obj, cookie=None):
        conn = http.client.HTTPConnection(base)
        body = json.dumps(obj).encode('utf-8')
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if cookie:
            headers["Cookie"] = cookie
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode('utf-8')
        set_cookie = resp.getheader("Set-Cookie") or ""
        conn.close()
        return f"{resp.status}|{set_cookie}|{data}"

    def get(path, cookie=None):
        conn = http.client.HTTPConnection(base)
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode('utf-8')
        conn.close()
        return f"{resp.status}|{data}"

    # Test 1: GET /me without cookie -> 401
    print("TEST1:" + get("/me"))

    # Test 2: POST /login wrong password -> 401
    print("TEST2:" + post_json("/login", {"username": "alice", "password": "wrong"}))

    # Test 3: POST /login correct -> 200 and Set-Cookie
    r3 = post_json("/login", {"username": "alice", "password": "p@ssw0rd-Example!"})
    print("TEST3:" + r3)
    parts = r3.split("|")
    set_cookie = parts[1] if len(parts) > 1 else ""
    cookie = ""
    if set_cookie.startswith("SID="):
        sc_end = set_cookie.find(";")
        cookie = set_cookie[:sc_end] if sc_end >= 0 else set_cookie

    # Test 4: GET /me with cookie
    print("TEST4:" + get("/me", cookie=cookie))

    # Test 5: POST /logout -> 200; then GET /me -> 401
    print("TEST5-1:" + post_json("/logout", {}, cookie=cookie))
    print("TEST5-2:" + get("/me", cookie=cookie))

    app.stop()