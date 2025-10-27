import secrets
import hmac
import hashlib
from typing import Dict, Optional

# Simple in-memory session and user store
_sessions: Dict[str, Dict[str, Optional[str]]] = {}
_SALT = "E8D4C9B4-Strong-Static-Salt-For-Demo-Only"

def _hash_password(username: str, password: str) -> str:
    h = hashlib.sha256()
    h.update(_SALT.encode())
    h.update(username.encode())
    h.update(b":")
    h.update(password.encode())
    return h.hexdigest()

_user_store: Dict[str, str] = {
    "admin": _hash_password("admin", "s3cureP@ss!")
}

def index() -> str:
    return "<html><body><h1>Welcome</h1><a href=\"/login\">Login</a></body></html>"

def init_session() -> str:
    sid = secrets.token_urlsafe(24)
    _sessions[sid] = {"username": None, "csrf": secrets.token_urlsafe(24)}
    return sid

def login_page(session_id: str) -> str:
    s = _sessions.get(session_id)
    if not s:
        return "ERROR: Invalid session"
    csrf = s["csrf"] or ""
    return (
        "<html><body><h1>Login</h1>"
        "<form method=\"POST\" action=\"/do_login\">"
        f"<input type=\"hidden\" name=\"csrf\" value=\"{_escape_html(csrf)}\"/>"
        "Username: <input type=\"text\" name=\"username\"/><br/>"
        "Password: <input type=\"password\" name=\"password\"/><br/>"
        "<button type=\"submit\">Login</button>"
        "</form></body></html>"
    )

def do_login(session_id: str, username: str, password: str, csrf_submitted: str) -> str:
    s = _sessions.get(session_id)
    if not s:
        return "ERROR: Invalid session"
    if not csrf_submitted or not hmac.compare_digest(csrf_submitted, s["csrf"] or ""):
        return "ERROR: CSRF validation failed"
    if username is None or password is None:
        return "ERROR: Missing credentials"
    stored = _user_store.get(username)
    provided = _hash_password(username, password)
    if stored and hmac.compare_digest(stored, provided):
        s["username"] = username
        s["csrf"] = secrets.token_urlsafe(24)  # rotate csrf
        return "REDIRECT:/secret"
    return "ERROR: Invalid username or password"

def secret_page(session_id: str) -> str:
    s = _sessions.get(session_id)
    if not s:
        return "ERROR: Invalid session"
    if s["username"] is None:
        return "REDIRECT:/login"
    return "<html><body><h1>Secret settings</h1></body></html>"

def _escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace("\"", "&quot;")
         .replace("'", "&#x27;")
    )

if __name__ == "__main__":
    # Test 1: Index
    print("TEST1 Index:")
    print(index())

    # New session
    sid = init_session()

    # Test 2: Login page
    print("\nTEST2 Login Page:")
    print(login_page(sid))
    csrf = _sessions[sid]["csrf"] or ""

    # Test 3: Wrong password
    print("\nTEST3 Wrong Password:")
    print(do_login(sid, "admin", "wrong", csrf))

    # Test 4: Wrong CSRF
    print("\nTEST4 Wrong CSRF:")
    print(do_login(sid, "admin", "s3cureP@ss!", "badtoken"))

    # Test 5: Successful login then secret
    print("\nTEST5 Successful Login and Secret:")
    print(do_login(sid, "admin", "s3cureP@ss!", csrf))
    print(secret_page(sid))