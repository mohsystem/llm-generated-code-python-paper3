import hmac

EXPECTED_USER = "admin"
EXPECTED_PASS = "S3cureP@ss"

def sanitize(s: str) -> str:
    if s is None:
        return ""
    filtered = ''.join(ch for ch in s if 32 <= ord(ch) <= 126)
    return filtered[:64].strip()

def constant_time_equals(a: str, b: str) -> bool:
    a = a if a is not None else ""
    b = b if b is not None else ""
    # hmac.compare_digest is constant-time for bytes/str of same type
    return hmac.compare_digest(a, b)

def index_page(session: dict) -> str:
    return '<html><body><h1>Index</h1><a href="/login">Login</a></body></html>'

def login_page() -> str:
    return ('<html><body><h1>Login</h1>'
            '<form method="POST" action="/do_login">'
            '<input type="text" name="username" maxlength="64"/>'
            '<input type="password" name="password" maxlength="64"/>'
            '<input type="submit" value="Login"/>'
            '</form></body></html>')

def do_login(username: str, password: str, session: dict) -> str:
    u = sanitize(username)
    p = sanitize(password)
    if not u or not p:
        return "REDIRECT:/login?error=1"
    ok_user = constant_time_equals(u, EXPECTED_USER)
    ok_pass = constant_time_equals(p, EXPECTED_PASS)
    if ok_user and ok_pass:
        session["username"] = u
        return "REDIRECT:/secret"
    return "REDIRECT:/login?error=1"

def secret_page(session: dict) -> str:
    if session is not None and session.get("username"):
        return "<html><body>Secret settings</body></html>"
    return "REDIRECT:/login"

def main():
    # Test case 1: Index page
    session1 = {}
    print("PY TC1 INDEX:", index_page(session1))

    # Test case 2: Secret without login
    session2 = {}
    print("PY TC2 SECRET (no login):", secret_page(session2))

    # Test case 3: Wrong password
    session3 = {}
    print("PY TC3 LOGIN wrong:", do_login("admin", "wrong", session3))
    print("PY TC3 SECRET after wrong:", secret_page(session3))

    # Test case 4: Correct login then secret
    session4 = {}
    print("PY TC4 LOGIN correct:", do_login("admin", "S3cureP@ss", session4))
    print("PY TC4 SECRET after correct:", secret_page(session4))

    # Test case 5: Empty credentials
    session5 = {}
    print("PY TC5 LOGIN empty:", do_login("", "", session5))
    print("PY TC5 SECRET after empty:", secret_page(session5))

if __name__ == "__main__":
    main()