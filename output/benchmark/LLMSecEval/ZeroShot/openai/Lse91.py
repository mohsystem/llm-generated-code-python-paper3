import base64
import hashlib
import os
import re
import secrets
import sqlite3
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

DB_PATH = "users_py.db"
PORT = 8081
MAX_BODY = 2048
ITERATIONS = 100_000
SALT_LEN = 16
KEY_LEN = 32

def init_db(db_path: str) -> None:
    con = sqlite3.connect(db_path)
    try:
        con.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, salt TEXT NOT NULL)")
        con.commit()
    finally:
        con.close()

def is_valid_username(u: str) -> bool:
    return isinstance(u, str) and re.fullmatch(r"[A-Za-z0-9_]{3,50}", u) is not None

def is_valid_password(p: str) -> bool:
    if not isinstance(p, str) or len(p) < 8 or len(p) > 200:
        return False
    has_letter = any(c.isalpha() for c in p)
    has_digit = any(c.isdigit() for c in p)
    return has_letter and has_digit

def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(SALT_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=KEY_LEN)
    return base64.b64encode(salt).decode("ascii"), base64.b64encode(dk).decode("ascii")

def register_user(db_path: str, username: str, password: str) -> str:
    if not is_valid_username(username):
        return "ERR: invalid username"
    if not is_valid_password(password):
        return "ERR: weak password"
    salt_b64, hash_b64 = hash_password(password)
    try:
        con = sqlite3.connect(db_path)
        with con:
            con.execute("INSERT INTO users(username, password_hash, salt) VALUES (?, ?, ?)", (username, hash_b64, salt_b64))
        return "OK: registered"
    except sqlite3.IntegrityError:
        return "ERR: username exists"
    except Exception:
        return "ERR: database error"
    finally:
        try:
            con.close()
        except Exception:
            pass

class RegisterHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            if self.path != "/register":
                self.send_error(404)
                return
            ctype = self.headers.get("Content-Type", "")
            if "application/x-www-form-urlencoded" not in ctype.lower():
                self.send_error(415)
                return
            cl = self.headers.get("Content-Length")
            if cl is None:
                self.send_error(411)
                return
            try:
                length = int(cl)
            except ValueError:
                self.send_error(400)
                return
            if length < 0 or length > MAX_BODY:
                self.send_error(413)
                return
            body = self.rfile.read(length)
            params = parse_qs(body.decode("utf-8"), keep_blank_values=True)
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            res = register_user(DB_PATH, username, password)
            if res.startswith("OK"):
                self.send_response(201)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Registered")
            elif "exists" in res:
                self.send_response(409)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Conflict")
            else:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Bad Request")
        except Exception:
            try:
                self.send_response(500)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Internal Server Error")
            except Exception:
                pass

def start_server():
    httpd = HTTPServer(("127.0.0.1", PORT), RegisterHandler)
    httpd.serve_forever()

if __name__ == "__main__":
    init_db(DB_PATH)
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    print("Python server started on http://127.0.0.1:%d" % PORT)
    # 5 Test cases (direct function calls)
    print("[Test1]", register_user(DB_PATH, "alice_01", "StrongPass123!"))
    print("[Test2]", register_user(DB_PATH, "alice_01", "AnotherStrong123!"))  # duplicate
    print("[Test3]", register_user(DB_PATH, "bad user!", "StrongPass123!"))    # invalid username
    print("[Test4]", register_user(DB_PATH, "bob", "123"))                     # weak password
    print("[Test5]", register_user(DB_PATH, "charlie_02", "Y3tAn0ther$trong"))