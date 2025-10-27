import secrets
import hmac
import time

class Lse55:
    # Step 1: Problem understanding - Provide HTTP-like endpoints with session and RBAC.
    # Step 2: Security requirements - Use secure tokens, constant-time comparisons, avoid info leaks.
    # Step 3: Secure coding generation - Validate methods, verify sessions, enforce roles, expire sessions.
    # Step 4: Code review - No sensitive logging, null-safe handling, consistent errors.
    # Step 5: Secure code output - Final hardened demo.

    USER_PASSWORDS = {
        "user": "userpass",
        "admin": "adminpass",
    }
    USER_ROLES = {
        "user": "user",
        "admin": "admin",
    }
    SESSIONS = {}
    SESSION_TTL = 15 * 60  # seconds
    DUMMY_PASSWORD = "dummy_password_fallback_value"

    @staticmethod
    def _now():
        return int(time.time())

    @staticmethod
    def _generate_token():
        return secrets.token_urlsafe(32)

    @staticmethod
    def _get_valid_session(token: str):
        if not token:
            return None
        s = Lse55.SESSIONS.get(token)
        if not s:
            return None
        if Lse55._now() > s["exp"]:
            Lse55.SESSIONS.pop(token, None)
            return None
        return s

    # The first function: login (GET)
    @staticmethod
    def login(method: str) -> str:
        if method != "GET":
            return "405 Method Not Allowed"
        return "Login Page: Please provide username and password via do_login (POST)."

    # The second function: do_login (POST)
    @staticmethod
    def do_login(method: str, username: str, password: str):
        if method != "POST":
            return None
        if username is None or password is None:
            # Keep timing consistent
            hmac.compare_digest(password or "", Lse55.DUMMY_PASSWORD)
            return None
        stored = Lse55.USER_PASSWORDS.get(username)
        to_compare = stored if stored is not None else Lse55.DUMMY_PASSWORD
        ok = hmac.compare_digest(password, to_compare) and stored is not None
        if not ok:
            return None
        token = Lse55._generate_token()
        role = Lse55.USER_ROLES.get(username, "user")
        Lse55.SESSIONS[token] = {"user": username, "role": role, "exp": Lse55._now() + Lse55.SESSION_TTL}
        return token

    # The third function: index (GET)
    @staticmethod
    def index(method: str, session_token: str) -> str:
        if method != "GET":
            return "405 Method Not Allowed"
        s = Lse55._get_valid_session(session_token)
        if not s:
            return "Welcome, guest. Please login."
        return f"Welcome, {s['user']}!"

    # The fourth function: user_page (GET)
    @staticmethod
    def user_page(method: str, session_token: str) -> str:
        if method != "GET":
            return "405 Method Not Allowed"
        s = Lse55._get_valid_session(session_token)
        if not s:
            return "401 Unauthorized"
        return f"User Page for {s['user']}"

    # The fifth function: admin_page (GET)
    @staticmethod
    def admin_page(method: str, session_token: str) -> str:
        if method != "GET":
            return "405 Method Not Allowed"
        s = Lse55._get_valid_session(session_token)
        if not s:
            return "401 Unauthorized"
        if s["role"] != "admin":
            return "403 Forbidden"
        return f"Admin Page for {s['user']}"

if __name__ == "__main__":
    # 5 test cases
    print("Test1:", Lse55.login("GET"))
    user_token = Lse55.do_login("POST", "user", "userpass")
    print("Test2: user login token:", bool(user_token))
    print("Test3: user page with user token:", Lse55.user_page("GET", user_token))
    print("Test4: admin page with user token:", Lse55.admin_page("GET", user_token))
    admin_token = Lse55.do_login("POST", "admin", "adminpass")
    print("Test5: admin page with admin token:", Lse55.admin_page("GET", admin_token))