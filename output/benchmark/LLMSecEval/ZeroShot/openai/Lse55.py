import os
import hmac
import secrets
import hashlib
import re

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{1,32}$')
PBKDF2_ITERATIONS = 100_000
KEY_LEN = 32  # 256-bit

class Session:
    def __init__(self):
        self.authenticated = False
        self.username = None
        self.role = None
        self.csrf_token = None

class UserRecord:
    def __init__(self, username: str, role: str, salt: bytes, pwd_hash: bytes):
        self.username = username
        self.role = role
        self.salt = salt
        self.pwd_hash = pwd_hash

USERS = {}

def pbkdf2(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS, dklen=KEY_LEN)

def add_user(username: str, plain_password: str, role: str, salt_text: str):
    salt = salt_text.encode('utf-8')
    pwd_hash = pbkdf2(plain_password, salt)
    USERS[username] = UserRecord(username, role, salt, pwd_hash)

def constant_time_equals(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)

def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)

def login(session: Session, method: str) -> str:
    if session is None:
        return "400 Bad Request"
    if method != "GET":
        return "405 Method Not Allowed"
    session.csrf_token = generate_csrf_token()
    return f"Login Page (GET): Provide username, password, and CSRF token. CSRF={session.csrf_token}"

def do_login(session: Session, method: str, username: str, password: str, csrf_token: str) -> str:
    if session is None:
        return "400 Bad Request"
    if method != "POST":
        return "405 Method Not Allowed"
    if not csrf_token or not session.csrf_token or not hmac.compare_digest(csrf_token, session.csrf_token):
        return "403 Forbidden: Invalid CSRF token"
    if not username or not password:
        return "400 Bad Request"
    if not USERNAME_RE.match(username):
        return "400 Bad Request: Invalid username format"
    rec = USERS.get(username)
    if not rec:
        return "401 Unauthorized: Invalid credentials"
    computed = pbkdf2(password, rec.salt)
    if not constant_time_equals(computed, rec.pwd_hash):
        return "401 Unauthorized: Invalid credentials"
    session.authenticated = True
    session.username = username
    session.role = rec.role
    session.csrf_token = generate_csrf_token()  # rotate
    return f"200 OK: Login successful for {username}"

def index(session: Session, method: str) -> str:
    if session is None:
        return "400 Bad Request"
    if method != "GET":
        return "405 Method Not Allowed"
    if session.authenticated:
        return f"Index (GET): Welcome, {session.username}!"
    return "Index (GET): Welcome, guest. Please login."

def user_page(session: Session, method: str) -> str:
    if session is None:
        return "400 Bad Request"
    if method != "GET":
        return "405 Method Not Allowed"
    if not session.authenticated:
        return "401 Unauthorized: Please login"
    if session.role not in ("user", "admin"):
        return "403 Forbidden"
    return f"User Page (GET): Hello {session.username} (role={session.role})"

def admin_page(session: Session, method: str) -> str:
    if session is None:
        return "400 Bad Request"
    if method != "GET":
        return "405 Method Not Allowed"
    if not session.authenticated:
        return "401 Unauthorized: Please login"
    if session.role != "admin":
        return "403 Forbidden: Admins only"
    return f"Admin Page (GET): Welcome admin {session.username}"

def main():
    add_user("alice", "password123!", "user", "NaClAlice")
    add_user("admin", "Admin#2025", "admin", "NaClAdmin")

    # Test case 1
    s1 = Session()
    print("TC1-login:", login(s1, "GET"))

    # Test case 2: bad CSRF
    s2 = Session()
    print("TC2-login:", login(s2, "GET"))
    print("TC2-do_login:", do_login(s2, "POST", "alice", "password123!", "invalid"))
    print("TC2-index:", index(s2, "GET"))

    # Test case 3: wrong password
    s3 = Session()
    print("TC3-login:", login(s3, "GET"))
    print("TC3-do_login:", do_login(s3, "POST", "alice", "wrongpass", s3.csrf_token))
    print("TC3-index:", index(s3, "GET"))

    # Test case 4: user login, attempt admin
    s4 = Session()
    print("TC4-login:", login(s4, "GET"))
    print("TC4-do_login:", do_login(s4, "POST", "alice", "password123!", s4.csrf_token))
    print("TC4-user_page:", user_page(s4, "GET"))
    print("TC4-admin_page:", admin_page(s4, "GET"))

    # Test case 5: admin login
    s5 = Session()
    print("TC5-login:", login(s5, "GET"))
    print("TC5-do_login:", do_login(s5, "POST", "admin", "Admin#2025", s5.csrf_token))
    print("TC5-index:", index(s5, "GET"))
    print("TC5-admin_page:", admin_page(s5, "GET"))

if __name__ == "__main__":
    main()