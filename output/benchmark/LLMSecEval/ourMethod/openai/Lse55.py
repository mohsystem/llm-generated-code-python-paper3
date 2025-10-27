import secrets
import hashlib
import hmac
import re
from typing import Dict, Tuple, Optional

# In-memory stores
USERS: Dict[str, Tuple[bytes, bytes, int, str]] = {}  # username -> (salt, hash, iterations, role)
SESSIONS: Dict[str, str] = {}  # token -> username

# Security constants
ITERATIONS = 210_000
SALT_LEN = 16
KEY_LEN = 32  # 256-bit

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")

def _password_policy(pw: str) -> bool:
    if not isinstance(pw, str):
        return False
    if len(pw) < 12 or len(pw) > 128:
        return False
    has_upper = any(c.isupper() for c in pw)
    has_lower = any(c.islower() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any(not c.isalnum() for c in pw)
    return has_upper and has_lower and has_digit and has_symbol

def _is_valid_username(u: str) -> bool:
    if not isinstance(u, str):
        return False
    if len(u) < 3 or len(u) > 64:
        return False
    return USERNAME_RE.fullmatch(u) is not None

def _hash_password(pw: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations, dklen=KEY_LEN)

def _gen_token(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)

def _register_user(username: str, password: str, role: str) -> bool:
    if not _is_valid_username(username):
        return False
    if role not in ("user", "admin"):
        return False
    if not _password_policy(password):
        return False
    salt = secrets.token_bytes(SALT_LEN)
    h = _hash_password(password, salt, ITERATIONS)
    USERS[username] = (salt, h, ITERATIONS, role)
    return True

def login(request_id: str) -> str:
    # GET /login
    if not isinstance(request_id, str) or len(request_id) > 128:
        return "400 Bad Request"
    return "Login endpoint (GET). Please POST to do_login."

def do_login(username: str, password: str) -> str:
    # POST /do_login
    if not _is_valid_username(username) or not isinstance(password, str) or len(password) == 0:
        return ""
    rec = USERS.get(username)
    if not rec:
        return ""
    salt, stored_hash, iterations, _role = rec
    calc = _hash_password(password, salt, iterations)
    if not hmac.compare_digest(calc, stored_hash):
        return ""
    token = _gen_token(32)
    SESSIONS[token] = username
    return token

def index(session_token: str) -> str:
    # GET /
    user = SESSIONS.get(session_token or "")
    if not user:
        return "401 Unauthorized"
    role = USERS.get(user, (b"", b"", 0, ""))[3]
    return f"Welcome, {user} (role={role})"

def user_page(session_token: str) -> str:
    # GET /user
    user = SESSIONS.get(session_token or "")
    if not user:
        return "401 Unauthorized"
    return f"User page for {user}"

def admin_page(session_token: str) -> str:
    # GET /admin
    user = SESSIONS.get(session_token or "")
    if not user:
        return "401 Unauthorized"
    role = USERS.get(user, (b"", b"", 0, ""))[3]
    if role != "admin":
        return "403 Forbidden"
    return f"Admin page for {user}"

def _gen_strong_password(length: int = 16) -> str:
    if length < 12:
        length = 12
    U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    L = "abcdefghijklmnopqrstuvwxyz"
    D = "0123456789"
    S = "!@#$%^&*()-_=+[]{}:,.?/"
    all_chars = U + L + D + S
    # ensure policy
    pw = [
        secrets.choice(U),
        secrets.choice(L),
        secrets.choice(D),
        secrets.choice(S),
    ]
    for _ in range(length - 4):
        pw.append(secrets.choice(all_chars))
    # shuffle
    for i in range(len(pw) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pw[i], pw[j] = pw[j], pw[i]
    return "".join(pw)

if __name__ == "__main__":
    print("== GET /login ==")
    print(login("req-1"))

    # Generate runtime strong passwords (not hard-coded)
    pw_userA = _gen_strong_password(16)
    pw_adminA = _gen_strong_password(18)
    pw_userB = _gen_strong_password(20)

    # Test 1: Register userA and login successfully
    print("\n== Test 1: userA successful login ==")
    _register_user("userA", pw_userA, "user")
    tok1 = do_login("userA", pw_userA)
    print("Token:", "(login failed)" if not tok1 else tok1)
    print("Index:", index(tok1))
    print("User page:", user_page(tok1))
    print("Admin page:", admin_page(tok1))

    # Test 2: Wrong password
    print("\n== Test 2: wrong password ==")
    tok2 = do_login("userA", "WrongPass123!")
    print("Token:", "(login failed)" if not tok2 else tok2)

    # Test 3: Admin registration and login
    print("\n== Test 3: adminA successful admin access ==")
    _register_user("adminA", pw_adminA, "admin")
    tok3 = do_login("adminA", pw_adminA)
    print("Token:", "(login failed)" if not tok3 else tok3)
    print("Admin page:", admin_page(tok3))

    # Test 4: Invalid token
    print("\n== Test 4: invalid token access ==")
    invalid_tok = "deadbeef"
    print("Index:", index(invalid_tok))
    print("Admin page:", admin_page(invalid_tok))

    # Test 5: Another user
    print("\n== Test 5: userB normal access, admin denied ==")
    _register_user("userB", pw_userB, "user")
    tok5 = do_login("userB", pw_userB)
    print("Token:", "(login failed)" if not tok5 else tok5)
    print("Index:", index(tok5))
    print("Admin page:", admin_page(tok5))