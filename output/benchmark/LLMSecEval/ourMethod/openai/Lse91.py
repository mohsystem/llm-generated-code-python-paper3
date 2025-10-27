import os
import sys
import re
import hmac
import json
import tempfile
import secrets
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

DB_MAGIC = "USRDB1"
PBKDF2_ITERATIONS = 210_000
SALT_LEN = 16  # 128-bit
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")


def is_strong_password(password: str) -> bool:
    if password is None:
        return False
    if len(password) < 12 or len(password) > 128:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    specials = set("!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~")
    has_special = any(c in specials for c in password)
    return has_upper and has_lower and has_digit and has_special


def _read_db(db_path: str):
    lines = []
    if not os.path.exists(db_path):
        return lines
    with open(db_path, "r", encoding="utf-8", newline="") as f:
        hdr = f.readline().rstrip("\n")
        if hdr != DB_MAGIC:
            raise IOError("Invalid DB header")
        lines.append(hdr)
        for line in f:
            if len(line) > 4096:
                raise IOError("Corrupt DB line")
            lines.append(line.rstrip("\n"))
    return lines


def _write_db_atomically(db_path: str, lines):
    dirn = os.path.dirname(os.path.abspath(db_path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix="usersdb_", suffix=".tmp", dir=dirn, text=True)
    try:
        try:
            os.fchmod(fd, 0o600)
        except Exception:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            for l in lines:
                f.write(l + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, db_path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def register_user(username: str, password: str, db_path: str) -> str:
    if username is None or password is None:
        return "Invalid input"
    if not USERNAME_RE.fullmatch(username):
        return "Invalid username format"
    if not is_strong_password(password):
        return "Password does not meet strength requirements"
    salt = secrets.token_bytes(SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)
    try:
        if os.path.exists(db_path):
            lines = _read_db(db_path)
        else:
            lines = [DB_MAGIC]
        for i in range(1, len(lines)):
            parts = lines[i].split("|")
            if len(parts) >= 4 and parts[0] == username:
                return "Username already exists"
        rec = "|".join([username, str(PBKDF2_ITERATIONS), salt.hex(), dk.hex()])
        lines.append(rec)
        _write_db_atomically(db_path, lines)
        return "Registered"
    except Exception:
        return "Internal error"


class RegisterHandler(BaseHTTPRequestHandler):
    server_version = "SecureReg/1.0"

    def do_POST(self):
        if self.path != "/register":
            self._send_json(404, {"error": "Not found"})
            return
        ctype = self.headers.get("Content-Type", "")
        if not ctype.lower().startswith("application/x-www-form-urlencoded"):
            self._send_json(400, {"error": "Unsupported content type"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 4096:
                self._send_json(413, {"error": "Request too large"})
                return
        except ValueError:
            self._send_json(411, {"error": "Invalid content length"})
            return
        body = self.rfile.read(length)
        try:
            params = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
        except Exception:
            self._send_json(400, {"error": "Bad form data"})
            return
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        res = register_user(username, password, self.server.db_path)
        if res == "Registered":
            self._send_json(200, {"status": "ok"})
        elif res == "Username already exists":
            self._send_json(409, {"error": res})
        elif res in ("Invalid username format", "Password does not meet strength requirements"):
            self._send_json(400, {"error": res})
        else:
            self._send_json(500, {"error": "Internal error"})

    def log_message(self, fmt, *args):
        # Suppress logging of sensitive data
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))

    def _send_json(self, code, obj):
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def start_server(db_path: str, host: str = "127.0.0.1", port: int = 8081):
    httpd = HTTPServer((host, port), RegisterHandler)
    httpd.db_path = db_path  # attach config
    print(f"Server running on http://{host}:{port}/register")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    db_file = "users_py.db"
    if not os.path.exists(db_file):
        _write_db_atomically(db_file, [DB_MAGIC])

    # 5 test cases
    tests = [
        ("alice_01", "Str0ng!Password#1"),
        ("alice_01", "Anoth3r!Str0ngPass"),  # duplicate
        ("bob", "N0tStrong"),  # weak
        ("X", "Weak123!"),  # invalid username and weak
        ("charlie-user", "V3ry$trongPassw0rd!")
    ]
    for i, (u, p) in enumerate(tests, 1):
        res = register_user(u, p, db_file)
        print(f"Test {i} register({u}): {res}")

    # Uncomment to run the HTTP server
    # start_server(db_file)