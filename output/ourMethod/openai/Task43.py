import time
import secrets
import hashlib
import hmac
from typing import Dict, Tuple, Optional, Any

# Data models
class User:
    def __init__(self, username: str, salt: bytes, pw_hash: bytes, created_at: int):
        self.username = username
        self.salt = salt
        self.pw_hash = pw_hash
        self.created_at = created_at

class Session:
    def __init__(self, token: str, username: str, expires_at: int):
        self.token = token
        self.username = username
        self.expires_at = expires_at

class Request:
    def __init__(self, method: str, path: str, headers: Dict[str, str], body: Dict[str, str]):
        self.method = method
        self.path = path
        self.headers = dict(headers)
        self.body = dict(body)

class Response:
    def __init__(self, status: int, headers: Dict[str, str], body: str):
        self.status = status
        self.headers = dict(headers)
        self.body = body

# Security parameters
SALT_LEN = 16
HASH_LEN = 32
PBKDF2_ITERATIONS = 210_000
SESSION_TTL_SECONDS = 1800
PASSWORD_MAX_AGE_SECONDS = 90 * 24 * 3600

# Validators
def valid_username(username: str) -> bool:
    if not isinstance(username, str):
        return False
    if len(username) < 3 or len(username) > 32:
        return False
    for c in username:
        if not (c.isalnum() or c in "_-"):
            return False
    return True

def strong_password(password: str) -> bool:
    if not isinstance(password, str):
        return False
    if len(password) < 12 or len(password) > 128:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_special

def safe_json(s: Any) -> str:
    if s is None:
        return ""
    t = str(s)
    return t.replace("\\", "\\").replace('"', '\\"')

def parse_cookie(cookie_header: str, name: str) -> Optional[str]:
    if not cookie_header:
        return None
    parts = cookie_header.split(";")
    for p in parts:
        p = p.strip()
        if "=" in p:
            k, v = p.split("=", 1)
            if k == name:
                return v
    return None

# Session Manager
class SessionManager:
    def __init__(self) -> None:
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=HASH_LEN)

    def register_user(self, username: str, password: str) -> Dict[str, Any]:
        if not valid_username(username):
            return {"ok": False, "error": "Invalid username"}
        if not strong_password(password):
            return {"ok": False, "error": "Weak password"}
        if username in self.users:
            return {"ok": False, "error": "User exists"}
        salt = secrets.token_bytes(SALT_LEN)
        pw_hash = self._hash_password(password, salt)
        self.users[username] = User(username, salt, pw_hash, int(time.time()))
        return {"ok": True}

    def login(self, username: str, password: str) -> Dict[str, Any]:
        user = self.users.get(username)
        if not user:
            return {"ok": False, "error": "Invalid credentials"}
        calc = self._hash_password(password, user.salt)
        if not hmac.compare_digest(calc, user.pw_hash):
            return {"ok": False, "error": "Invalid credentials"}
        now = int(time.time())
        if now - user.created_at > PASSWORD_MAX_AGE_SECONDS:
            return {"ok": False, "error": "Password expired"}
        token = secrets.token_hex(32)
        self.sessions[token] = Session(token, username, now + SESSION_TTL_SECONDS)
        return {"ok": True, "token": token}

    def me(self, token: Optional[str]) -> Dict[str, Any]:
        self.cleanup_expired_sessions()
        if not token:
            return {"ok": False, "error": "No session"}
        s = self.sessions.get(token)
        if not s or s.expires_at < int(time.time()):
            return {"ok": False, "error": "Invalid or expired session"}
        return {"ok": True, "username": s.username}

    def logout(self, token: Optional[str]) -> Dict[str, Any]:
        if token and token in self.sessions:
            del self.sessions[token]
        return {"ok": True}

    def cleanup_expired_sessions(self) -> None:
        now = int(time.time())
        expired = [t for t, s in self.sessions.items() if s.expires_at < now]
        for t in expired:
            del self.sessions[t]

# Web simulation
class WebApp:
    def __init__(self, mgr: SessionManager) -> None:
        self.mgr = mgr

    def handle(self, req: Request) -> Response:
        if req.path == "/register":
            if req.method != "POST":
                return self._json(405, "Method Not Allowed")
            username = req.body.get("username", "")
            password = req.body.get("password", "")
            r = self.mgr.register_user(username, password)
            if r.get("ok"):
                return self._json(201, '{"status":"registered"}')
            return self._json(400, f'{{"error":"{safe_json(r.get("error"))}"}}')
        elif req.path == "/login":
            if req.method != "POST":
                return self._json(405, "Method Not Allowed")
            username = req.body.get("username", "")
            password = req.body.get("password", "")
            r = self.mgr.login(username, password)
            if r.get("ok"):
                token = r.get("token", "")
                headers = {"Set-Cookie": f"SID={token}; HttpOnly; Secure; SameSite=Strict; Path=/"}
                return Response(200, headers, '{"status":"ok"}')
            return self._json(401, f'{{"error":"{safe_json(r.get("error"))}"}}')
        elif req.path == "/me":
            if req.method != "GET":
                return self._json(405, "Method Not Allowed")
            cookie = req.headers.get("Cookie", "")
            sid = parse_cookie(cookie, "SID")
            r = self.mgr.me(sid)
            if r.get("ok"):
                return self._json(200, f'{{"username":"{safe_json(r.get("username"))}"}}')
            return self._json(401, f'{{"error":"{safe_json(r.get("error"))}"}}')
        elif req.path == "/logout":
            if req.method != "POST":
                return self._json(405, "Method Not Allowed")
            cookie = req.headers.get("Cookie", "")
            sid = parse_cookie(cookie, "SID")
            self.mgr.logout(sid)
            headers = {"Set-Cookie": "SID=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"}
            return Response(200, headers, '{"status":"logged_out"}')
        else:
            return self._json(404, '{"error":"not_found"}')

    def _json(self, status: int, body: str) -> Response:
        return Response(status, {"Content-Type": "application/json; charset=utf-8"}, body)

if __name__ == "__main__":
    mgr = SessionManager()
    app = WebApp(mgr)

    # Test 1: Register
    r1 = app.handle(Request("POST", "/register", {}, {"username": "alice_1", "password": "Str0ng!Passw0rd"}))
    print(f"T1 status={r1.status} body={r1.body}")

    # Test 2: Weak password
    r2 = app.handle(Request("POST", "/register", {}, {"username": "bob", "password": "weak"}))
    print(f"T2 status={r2.status} body={r2.body}")

    # Test 3: Login
    r3 = app.handle(Request("POST", "/login", {}, {"username": "alice_1", "password": "Str0ng!Passw0rd"}))
    set_cookie = r3.headers.get("Set-Cookie", "")
    print(f"T3 status={r3.status} set-cookie-present={bool(set_cookie)}")

    # Test 4: /me
    cookie_header = set_cookie.split(";", 1)[0]
    r4 = app.handle(Request("GET", "/me", {"Cookie": cookie_header}, {}))
    print(f"T4 status={r4.status} body={r4.body}")

    # Test 5: logout then /me should fail
    r5 = app.handle(Request("POST", "/logout", {"Cookie": cookie_header}, {}))
    r6 = app.handle(Request("GET", "/me", {"Cookie": cookie_header}, {}))
    print(f"T5 logout-status={r5.status} me-after-logout-status={r6.status}")