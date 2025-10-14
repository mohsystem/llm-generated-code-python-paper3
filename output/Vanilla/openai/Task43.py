import http.server
import socketserver
import threading
import time
import secrets
import urllib.parse
import http.client

class Session:
    def __init__(self, token: str, user: str, expires_at: float):
        self.token = token
        self.user = user
        self.expires_at = expires_at

class SessionManager:
    def __init__(self, ttl_seconds: int):
        self.ttl = ttl_seconds
        self.sessions = {}
        self.lock = threading.Lock()
        self._start_cleaner()

    def _start_cleaner(self):
        def cleaner():
            while True:
                time.sleep(self.ttl)
                now = time.time()
                with self.lock:
                    to_del = [k for k, s in self.sessions.items() if s.expires_at < now]
                    for k in to_del:
                        del self.sessions[k]
        t = threading.Thread(target=cleaner, daemon=True)
        t.start()

    def create_session(self, user: str) -> str:
        token = secrets.token_hex(32)
        exp = time.time() + self.ttl
        with self.lock:
            self.sessions[token] = Session(token, user, exp)
        return token

    def validate(self, token: str):
        if not token:
            return None
        with self.lock:
            s = self.sessions.get(token)
            if not s:
                return None
            if s.expires_at < time.time():
                del self.sessions[token]
                return None
            return s

    def terminate(self, token: str) -> bool:
        if not token:
            return False
        with self.lock:
            return self.sessions.pop(token, None) is not None

class WebAppHandler(http.server.BaseHTTPRequestHandler):
    session_manager = None
    cookie_name = "SESSIONID"
    cookie_max_age = 900

    def do_GET(self):
        if self.path.startswith("/login"):
            self.handle_login()
        elif self.path.startswith("/me"):
            self.handle_me()
        elif self.path.startswith("/logout"):
            self.handle_logout()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def parse_query(self):
        parsed = urllib.parse.urlparse(self.path)
        return dict(urllib.parse.parse_qsl(parsed.query))

    def get_cookie(self):
        h = self.headers.get("Cookie")
        if not h:
            return None
        parts = [p.strip() for p in h.split(";")]
        for p in parts:
            if p.startswith(self.cookie_name + "="):
                return p.split("=", 1)[1]
        return None

    def set_cookie(self, token: str, expire_now: bool = False):
        if expire_now:
            value = f"{self.cookie_name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
        else:
            value = f"{self.cookie_name}={token}; Path=/; Max-Age={self.cookie_max_age}; HttpOnly; SameSite=Lax"
        self.send_header("Set-Cookie", value)

    def handle_login(self):
        q = self.parse_query()
        user = q.get("user", "guest")
        token = self.session_manager.create_session(user)
        body = f'{{"status":"ok","user":"{user}"}}'.encode()
        self.send_response(200)
        self.set_cookie(token, expire_now=False)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_me(self):
        token = self.get_cookie()
        s = self.session_manager.validate(token)
        if not s:
            body = b'{"error":"unauthorized"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = f'{{"user":"{s.user}","expiresAt":"{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(s.expires_at))}"}}'.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_logout(self):
        token = self.get_cookie()
        ok = self.session_manager.terminate(token)
        if ok:
            body = b'{"status":"logged_out"}'
        else:
            body = b'{"status":"no_session"}'
        self.send_response(200)
        self.set_cookie("", expire_now=True)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run_server(port=8086):
    WebAppHandler.session_manager = SessionManager(ttl_seconds=900)
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", port), WebAppHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd

def run_tests(port=8086):
    conn = http.client.HTTPConnection("127.0.0.1", port)
    session_cookie = None

    # Test 1: /me without cookie -> 401
    conn.request("GET", "/me")
    r1 = conn.getresponse()
    print("Test1 status:", r1.status, "body:", r1.read().decode())

    # Test 2: /login?user=bob -> 200 + Set-Cookie
    conn.request("GET", "/login?user=bob")
    r2 = conn.getresponse()
    set_cookie = r2.getheader("Set-Cookie")
    body2 = r2.read().decode()
    print("Test2 status:", r2.status, "body:", body2)
    if set_cookie:
        # Extract SESSIONID=...
        parts = set_cookie.split(";")
        for p in parts:
            p = p.strip()
            if p.startswith("SESSIONID="):
                session_cookie = p
                break

    # Test 3: /me with cookie -> 200
    headers = {}
    if session_cookie:
        headers["Cookie"] = session_cookie
    conn.request("GET", "/me", headers=headers)
    r3 = conn.getresponse()
    print("Test3 status:", r3.status, "body:", r3.read().decode())

    # Test 4: /logout with cookie -> 200
    headers = {}
    if session_cookie:
        headers["Cookie"] = session_cookie
    conn.request("GET", "/logout", headers=headers)
    r4 = conn.getresponse()
    print("Test4 status:", r4.status, "body:", r4.read().decode())

    # Test 5: /me with same cookie -> 401
    headers = {}
    if session_cookie:
        headers["Cookie"] = session_cookie
    conn.request("GET", "/me", headers=headers)
    r5 = conn.getresponse()
    print("Test5 status:", r5.status, "body:", r5.read().decode())

if __name__ == "__main__":
    server = run_server(8086)
    time.sleep(0.2)
    run_tests(8086)
    server.shutdown()
    server.server_close()