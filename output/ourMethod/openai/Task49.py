import http.server
import socketserver
import threading
import urllib.parse
import json
import http.client
from typing import Dict, Optional, Tuple

MAX_BODY_SIZE = 4096

class InMemoryDB:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next_id = 1
        self._users: Dict[int, Dict[str, object]] = {}

    def add_user(self, username: str, email: str, age: int) -> int:
        with self._lock:
            uid = self._next_id
            self._next_id += 1
            self._users[uid] = {"id": uid, "username": username, "email": email, "age": age}
            return uid

    def size(self) -> int:
        with self._lock:
            return len(self._users)

DB = InMemoryDB()

def is_valid_username(s: Optional[str]) -> bool:
    if s is None:
        return False
    if not (3 <= len(s) <= 20):
        return False
    for ch in s:
        if not (ch.isalnum() or ch == '_'):
            return False
    return True

def is_valid_email(s: Optional[str]) -> bool:
    if s is None:
        return False
    if len(s) > 320 or '@' not in s:
        return False
    try:
        local, domain = s.split('@', 1)
    except ValueError:
        return False
    if not local or not domain or '.' not in domain:
        return False
    tld = domain.rsplit('.', 1)[-1]
    if not (2 <= len(tld) <= 63) or not tld.isalpha():
        return False
    allowed_local = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-")
    allowed_domain = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-")
    if any(ch not in allowed_local for ch in local):
        return False
    if any(ch not in allowed_domain for ch in domain):
        return False
    return True

def is_valid_age(s: Optional[str]) -> bool:
    if s is None or len(s) > 3:
        return False
    if not s.isdigit():
        return False
    v = int(s)
    return 1 <= v <= 120

class UsersHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SecureSimpleAPI/1.0"

    def do_POST(self) -> None:
        try:
            if self.path != "/users":
                self._send_json(404, {"error": "not_found"})
                return
            ctype = self.headers.get("Content-Type", "")
            if not ctype.lower().startswith("application/x-www-form-urlencoded"):
                self._send_json(415, {"error": "unsupported_media_type"})
                return
            cl = self.headers.get("Content-Length")
            if cl is None:
                self._send_json(411, {"error": "length_required"})
                return
            try:
                length = int(cl)
            except ValueError:
                self._send_json(400, {"error": "bad_length"})
                return
            if length < 0 or length > MAX_BODY_SIZE:
                self._send_json(413, {"error": "payload_too_large"})
                return

            body = self.rfile.read(length)
            if len(body) != length:
                self._send_json(400, {"error": "incomplete_body"})
                return

            try:
                form = urllib.parse.parse_qs(body.decode("utf-8"), strict_parsing=True, keep_blank_values=True)
            except Exception:
                self._send_json(400, {"error": "invalid_form"})
                return

            def one(field: str) -> Optional[str]:
                vals = form.get(field)
                if not vals:
                    return None
                v = vals[0]
                if v is None:
                    return None
                if len(v) > 256:
                    return None
                return v

            username = one("username")
            email = one("email")
            age = one("age")

            if not (is_valid_username(username) and is_valid_email(email) and is_valid_age(age)):
                self._send_json(400, {"error": "invalid_input"})
                return

            uid = DB.add_user(username, email, int(age))
            self._send_json(201, {"id": uid, "status": "created"})
        except Exception:
            self._send_json(500, {"error": "internal_error"})

    def log_message(self, format: str, *args) -> None:
        # Quiet handler to avoid noisy test output
        return

    def _send_json(self, code: int, obj: Dict[str, object]) -> None:
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def run_server(server_ready: threading.Event) -> Tuple[socketserver.TCPServer, int]:
    class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

    httpd = ThreadingTCPServer(("127.0.0.1", 0), UsersHandler)
    port = httpd.server_address[1]
    server_ready.port = port  # type: ignore
    server_ready.set()
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()

def client_post(port: int, body: str) -> Tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
        conn.request("POST", "/users", body=body.encode("utf-8"), headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        try:
            text = data.decode("utf-8")
        except Exception:
            text = ""
        return resp.status, text
    finally:
        conn.close()

if __name__ == "__main__":
    ready = threading.Event()
    t = threading.Thread(target=run_server, args=(ready,), daemon=True)
    t.start()
    ready.wait(timeout=5)
    port = getattr(ready, "port", None)  # type: ignore
    if not isinstance(port, int):
        raise SystemExit("Server failed to start")

    tests = [
        "username=alice_01&email=alice%40example.com&age=30",
        "username=bob&email=invalid_email&age=25",
        "username=ch&email=charlie%40example.com&age=22",
        "username=david12345678901234567890&email=david%40example.com&age=40",
        "username=eve_ok&email=eve.ok%2Btag%40example.co&age=27",
    ]
    for i, body in enumerate(tests, 1):
        code, text = client_post(port, body)
        print(f"Test {i} HTTP {code} -> {text}")

    print(f"Users stored: {DB.size()}")