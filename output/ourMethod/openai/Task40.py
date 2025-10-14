#!/usr/bin/env python3
import http.server
import socketserver
from http import HTTPStatus
from typing import Dict, Tuple, List
import urllib.parse
import hmac
import secrets
import re
import time

PORT = 8081
SESSIONS: Dict[str, Dict[str, object]] = {}
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,10}$")
MAX_BODY_BYTES = 8 * 1024

def constant_time_equals(a: str, b: str) -> bool:
    if a is None or b is None:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))

def validate_user_input(display_name: str, email: str) -> List[str]:
    errors: List[str] = []
    if not display_name or display_name.strip() == "":
        errors.append("Display name is required.")
    elif len(display_name) > 50:
        errors.append("Display name too long (max 50).")
    if not email or email.strip() == "":
        errors.append("Email is required.")
    elif len(email) > 320 or EMAIL_RE.match(email) is None:
        errors.append("Invalid email format.")
    return errors

def apply_settings_update(session: Dict[str, object], display_name: str, email: str, provided_csrf: str) -> str:
    if session is None or provided_csrf is None:
        return "FORBIDDEN"
    expected = session.get("csrf")
    if not constant_time_equals(provided_csrf, expected if isinstance(expected, str) else ""):
        return "FORBIDDEN"
    errors = validate_user_input(display_name, email)
    if errors:
        return "ERROR: " + " ".join(errors)
    session["settings"] = {"displayName": display_name, "email": email}
    # Rotate CSRF after success
    session["csrf"] = secrets.token_hex(32)
    return "OK"

def html_escape(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

def parse_form_urlencoded(body: str) -> Dict[str, str]:
    res: Dict[str, str] = {}
    for k, v in urllib.parse.parse_qs(body, keep_blank_values=True, strict_parsing=False).items():
        res[k] = v[0] if v else ""
    return res

def rfc1123_expires(seconds: int) -> str:
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + seconds))

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "SecureSettingsServer/1.0"

    def log_message(self, format, *args):
        # Reduce noisy logging in this demo
        pass

    def do_GET(self):
        if self.path != "/settings":
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        sid, session = self.get_or_create_session()
        # Issue new CSRF for form
        session["csrf"] = secrets.token_hex(32)
        page = self.render_settings_page(session)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.set_session_cookie(sid)
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))

    def do_POST(self):
        if self.path != "/settings":
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return
        ct = self.headers.get("Content-Type", "")
        if not ct.startswith("application/x-www-form-urlencoded"):
            self.send_error(HTTPStatus.BAD_REQUEST, "Bad Request")
            return
        sid, session = self.get_or_create_session()
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_error(HTTPStatus.BAD_REQUEST, "Bad Request")
            return
        body_bytes = self.rfile.read(length)
        try:
            body = body_bytes.decode("utf-8", errors="strict")
        except Exception:
            self.send_error(HTTPStatus.BAD_REQUEST, "Bad Request")
            return
        form = parse_form_urlencoded(body)
        display_name = form.get("displayName", "")
        email = form.get("email", "")
        csrf = form.get("csrf", "")
        result = apply_settings_update(session, display_name, email, csrf)
        if result == "FORBIDDEN":
            self.send_response(HTTPStatus.FORBIDDEN)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.set_session_cookie(sid)
            self.end_headers()
            self.wfile.write(b"Forbidden")
            return
        if result.startswith("ERROR:"):
            page = self.render_settings_page_with_errors(session, [e for e in result[len("ERROR:"):].strip().split(". ") if e])
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.set_session_cookie(sid)
            self.end_headers()
            self.wfile.write(page.encode("utf-8"))
            return
        page = self.render_settings_page_with_success(session, "Settings updated successfully.")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.set_session_cookie(sid)
        self.end_headers
        self.wfile.write(page.encode("utf-8"))

    def get_or_create_session(self) -> Tuple[str, Dict[str, object]]:
        cookies = self.headers.get_all("Cookie", failobj=[])
        sid = None
        for header in cookies:
            for part in header.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    if k == "SID":
                        sid = v.strip()
                        break
        if sid and sid in SESSIONS:
            return sid, SESSIONS[sid]
        sid = secrets.token_hex(24)
        sess = {"csrf": secrets.token_hex(32), "settings": {"displayName": "User", "email": "user@example.com"}}
        SESSIONS[sid] = sess
        return sid, sess

    def set_session_cookie(self, sid: str) -> None:
        cookie = f"SID={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600; Expires={rfc1123_expires(3600)}"
        self.send_header("Set-Cookie", cookie)

    def render_settings_page(self, session: Dict[str, object]) -> str:
        s = session.get("settings", {})
        dn = html_escape(str(s.get("displayName", "")))
        em = html_escape(str(s.get("email", "")))
        csrf = html_escape(str(session.get("csrf", "")))
        return f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv='Content-Security-Policy' content="default-src 'none'; style-src 'self' 'unsafe-inline'; form-action 'self'">
<title>User Settings</title></head>
<body>
<h1>User Settings</h1>
<form method="POST" action="/settings">
<input type="hidden" name="csrf" value="{csrf}">
<label>Display Name: <input type="text" name="displayName" maxlength="50" value="{dn}"></label><br>
<label>Email: <input type="email" name="email" maxlength="320" value="{em}"></label><br>
<button type="submit">Update</button>
</form>
</body></html>"""

    def render_settings_page_with_errors(self, session: Dict[str, object], errors: List[str]) -> str:
        base = self.render_settings_page(session)
        items = "".join([f"<li>{html_escape(e.strip())}</li>" for e in errors if e])
        return base.replace("<h1>User Settings</h1>", "<h1>User Settings</h1>" + f"<ul style='color:red;'>{items}</ul>")

    def render_settings_page_with_success(self, session: Dict[str, object], msg: str) -> str:
        base = self.render_settings_page(session)
        return base.replace("<h1>User Settings</h1>", "<h1>User Settings</h1>" + f"<p style='color:green;'>{html_escape(msg)}</p>")

def run_tests() -> None:
    # Create a session
    sid = secrets.token_hex(24)
    session = {"csrf": secrets.token_hex(32), "settings": {"displayName": "User", "email": "user@example.com"}}
    SESSIONS[sid] = session

    # 1) Valid case
    res1 = apply_settings_update(session, "Alice", "alice@example.com", session["csrf"])
    print("Test1 (valid):", res1 == "OK")

    # 2) Invalid CSRF
    res2 = apply_settings_update(session, "Bob", "bob@example.com", "deadbeef")
    print("Test2 (invalid CSRF):", res2 == "FORBIDDEN")

    # 3) Too long name
    res3 = apply_settings_update(session, "A" * 51, "ok@example.com", session["csrf"])
    print("Test3 (long name):", res3.startswith("ERROR:"))

    # 4) Invalid email
    res4 = apply_settings_update(session, "Charlie", "not-an-email", session["csrf"])
    print("Test4 (bad email):", res4.startswith("ERROR:"))

    # 5) Missing required
    res5 = apply_settings_update(session, "", "", session["csrf"])
    print("Test5 (missing):", res5.startswith("ERROR:"))

if __name__ == "__main__":
    print("Running tests...")
    run_tests()
    with socketserver.TCPServer(("localhost", PORT), Handler) as httpd:
        print(f"Server running on http://localhost:{PORT}/settings")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()