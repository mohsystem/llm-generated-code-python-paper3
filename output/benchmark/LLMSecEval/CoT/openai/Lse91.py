# Chain-of-Through process:
# 1) Problem understanding: Provide a minimal web server handling registration with username/password. Validate inputs, hash password with strong KDF and salt, store to in-memory DB. Also provide a function to register returning output.
# 2) Security requirements: Use PBKDF2-HMAC-SHA256, random salt, input validation, size limits, avoid logging secrets.
# 3) Secure coding generation: Implement robust handler, content length checks, safe parsing, and deterministic responses.
# 4) Code review: Ensure no sensitive prints, safe dict usage, and bounded operations.
# 5) Secure code output: Final code below.

import base64
import hashlib
import hmac
import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

# In-memory "database": username -> "base64(salt):base64(hash)"
DB = {}

USERNAME_MIN = 3
USERNAME_MAX = 32
PASSWORD_MIN = 8
PASSWORD_MAX = 1024
SALT_LEN = 16
ITERATIONS = 200_000
MAX_BODY_SIZE = 4096

def _valid_username(u: str) -> bool:
    if not isinstance(u, str):
        return False
    if len(u) < USERNAME_MIN or len(u) > USERNAME_MAX:
        return False
    for ch in u:
        if not (ch.isalnum() or ch == "_"):
            return False
    return True

def _hash_password(password: str, salt: bytes, iterations: int = ITERATIONS) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    return f"{base64.b64encode(salt).decode()}:{base64.b64encode(dk).decode()}"

def register_user(username: str, password: str) -> str:
    if username is None or password is None:
        return "error: invalid input"
    if not _valid_username(username):
        return "error: invalid username"
    if len(password) < PASSWORD_MIN or len(password) > PASSWORD_MAX:
        return "error: invalid password length"
    if username in DB:
        return "error: username already exists"
    salt = secrets.token_bytes(SALT_LEN)
    record = _hash_password(password, salt, ITERATIONS)
    DB[username] = record
    return "ok"

class RegisterHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/register":
            self._send_json(404, {"status": "error", "message": "not found"})
            return
        length_header = self.headers.get("Content-Length")
        if not length_header:
            self._send_json(411, {"status": "error", "message": "length required"})
            return
        try:
            length = int(length_header)
        except Exception:
            self._send_json(400, {"status": "error", "message": "bad length"})
            return
        if length <= 0 or length > MAX_BODY_SIZE:
            self._send_json(400, {"status": "error", "message": "invalid length"})
            return
        ctype = self.headers.get("Content-Type") or ""
        if "application/x-www-form-urlencoded" not in ctype.lower():
            self._send_json(400, {"status": "error", "message": "unsupported content type"})
            return
        body = self.rfile.read(length)
        try:
            params = parse_qs(body.decode("utf-8"), strict_parsing=True, keep_blank_values=True)
        except Exception:
            self._send_json(400, {"status": "error", "message": "bad form data"})
            return
        username = params.get("username", [None])[0]
        password = params.get("password", [None])[0]
        if username is None or password is None:
            self._send_json(400, {"status": "error", "message": "missing fields"})
            return
        result = register_user(username, password)
        if result == "ok":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(400, {"status": "error", "message": result})

    def log_message(self, format, *args):
        # Suppress default logging to avoid leaking details
        return

    def _send_json(self, code, obj):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def main():
    # 5 test cases
    print(register_user("user_one", "StrongPass123!"))   # ok
    print(register_user("user_one", "AnotherPass123!"))  # duplicate
    print(register_user("u!", "bad"))                    # invalid username
    print(register_user("shortpwd", "123"))              # short password
    print(register_user("second_user", "Another#Strong$Pass456"))  # ok

    # Start server on port 8081 (optional manual testing)
    # curl -X POST -d "username=tester&password=TestPass123!" http://localhost:8081/register
    httpd = HTTPServer(("0.0.0.0", 8081), RegisterHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

if __name__ == "__main__":
    main()