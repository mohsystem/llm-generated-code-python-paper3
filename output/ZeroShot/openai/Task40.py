# Web application in Python with CSRF protection using standard library http.server
# - Starts an HTTP server on port 8081
# - Endpoints:
#   GET  /settings -> Renders settings form with CSRF token bound to session cookie
#   POST /update   -> Validates Origin/Referer and CSRF token, updates settings
# Security:
#   - Sessions via HttpOnly, SameSite=Strict cookie
#   - CSRF token generated with secrets.token_urlsafe
#   - Strict Content-Type enforcement, request size limit
#   - Security headers and HTML escaping
#   - Input validation

from http.server import HTTPServer, BaseHTTPRequestHandler
import secrets
import base64
import time
from urllib.parse import parse_qs
import html

SESSIONS = {}  # sid -> dict(csrf, display_name, email_notif, last_access)
MAX_BODY = 8 * 1024

def generate_token(num_bytes: int) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(num_bytes)).decode('ascii').rstrip('=')

def constant_time_equals(a: str, b: str) -> bool:
    if a is None or b is None:
        return False
    if len(a) != len(b):
        # normalize to equal length
        maxlen = max(len(a), len(b))
        a = (a + '\0' * (maxlen - len(a)))
        b = (b + '\0' * (maxlen - len(b)))
    res = 0
    for x, y in zip(a.encode('utf-8'), b.encode('utf-8')):
        res |= x ^ y
    return res == 0

def validate_csrf(session_token: str, provided_token: str) -> bool:
    return constant_time_equals(session_token, provided_token)

def html_escape(s: str) -> str:
    return html.escape(s or "", quote=True)

def sanitize_display_name(s: str) -> str:
    if not s:
        return "Anonymous"
    s = s.strip()
    if len(s) > 50:
        s = s[:50]
    import re
    if not re.fullmatch(r"[\w \-\p{L}\p{N}]{1,50}", s, flags=re.UNICODE):
        # Keep it simple: allow letters, numbers, underscore, space, hyphen
        if not re.fullmatch(r"[A-Za-z0-9 _\-]{1,50}", s):
            return "Anonymous"
    return s

def build_settings_form(csrf_token: str, display_name: str, email_notif: bool) -> str:
    dn = html_escape(display_name)
    checked = "checked" if email_notif else ""
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>User Settings</title></head>
<body>
<h1>Update Settings</h1>
<form method="POST" action="/update">
<label for="displayName">Display Name:</label>
<input id="displayName" name="displayName" maxlength="50" value="{dn}" required>
<br><label><input type="checkbox" name="emailNotif" value="1" {checked}> Email Notifications</label>
<input type="hidden" name="_csrf" value="{html_escape(csrf_token)}">
<br><button type="submit">Save</button>
</form>
<p>CSRF token is bound to your session and validated on submit.</p>
</body></html>"""

def add_security_headers(handler: BaseHTTPRequestHandler):
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")

def get_or_create_session(handler: BaseHTTPRequestHandler):
    cookies = handler.headers.get_all('Cookie') or []
    sid = None
    for header in cookies:
        parts = header.split(';')
        for part in parts:
            if '=' in part:
                k, v = part.strip().split('=', 1)
                if k == 'SID':
                    sid = v
    sess = None
    if sid and sid in SESSIONS:
        sess = SESSIONS[sid]
        sess['last_access'] = int(time.time())
    else:
        sid = generate_token(24)
        sess = {'csrf': None, 'display_name': 'Anonymous', 'email_notif': False, 'last_access': int(time.time())}
        SESSIONS[sid] = sess
        # HttpOnly + SameSite=Strict; omit Secure for local http
        handler.send_header('Set-Cookie', f"SID={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400")
    return sid, sess

def origin_allowed(handler: BaseHTTPRequestHandler) -> bool:
    host = handler.headers.get('Host') or "localhost:8081"
    expected = f"http://{host}"
    origin = handler.headers.get('Origin')
    referer = handler.headers.get('Referer')
    if origin:
        return origin.lower() == expected.lower()
    if referer:
        return referer.lower().startswith(expected.lower() + "/")
    return False

class App(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split('?', 1)[0] == "/settings":
            self.handle_settings()
        else:
            self.handle_root()

    def do_POST(self):
        if self.path.split('?', 1)[0] == "/update":
            self.handle_update()
        else:
            self.send_error(404, "Not Found")

    def handle_root(self):
        self.send_response(200)
        sid, sess = get_or_create_session(self)
        add_security_headers(self)
        body = f"""<!doctype html><html><head><meta charset="utf-8"><title>Home</title></head>
<body><h1>Welcome</h1><p>Hello, {html_escape(sess['display_name'])}</p><p><a href="/settings">Go to Settings</a></p></body></html>"""
        body_bytes = body.encode('utf-8')
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def handle_settings(self):
        self.send_response(200)
        sid, sess = get_or_create_session(self)
        # Rotate CSRF token on render
        sess['csrf'] = generate_token(32)
        add_security_headers(self)
        body = build_settings_form(sess['csrf'], sess['display_name'], sess['email_notif'])
        body_bytes = body.encode('utf-8')
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def handle_update(self):
        if not origin_allowed(self):
            self.send_error(403, "Forbidden")
            return
        ctype = self.headers.get('Content-Type') or ""
        if not ctype.lower().startswith("application/x-www-form-urlencoded"):
            self.send_error(415, "Unsupported Media Type")
            return
        cl = self.headers.get('Content-Length')
        try:
            length = int(cl) if cl else 0
        except ValueError:
            self.send_error(400, "Bad Request")
            return
        if length < 0 or length > MAX_BODY:
            self.send_error(413, "Payload Too Large")
            return
        body = self.rfile.read(length).decode('utf-8', 'strict')
        form = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}

        self.send_response(200)  # Provisional; may change to 403
        sid, sess = get_or_create_session(self)

        token = form.get('_csrf')
        if not validate_csrf(sess.get('csrf'), token):
            # Overwrite response to 403
            self.send_response_only(403)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(b"Forbidden")
            return

        dn = sanitize_display_name(form.get('displayName'))
        en = form.get('emailNotif') == '1'
        sess['display_name'] = dn
        sess['email_notif'] = en
        # Rotate token after success
        sess['csrf'] = generate_token(32)

        add_security_headers(self)
        body = f"""<!doctype html><html><head><meta charset="utf-8"><title>Saved</title></head>
<body><h2>Settings updated securely.</h2>
<p>Display Name: {html_escape(sess['display_name'])}</p>
<p>Email Notifications: {"Enabled" if sess['email_notif'] else "Disabled"}</p>
<p><a href="/settings">Back to Settings</a></p>
</body></html>"""
        body_bytes = body.encode('utf-8')
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

def run_tests():
    print("[Python] Running tests...")
    # 1) Token uniqueness
    toks = set(generate_token(16) for _ in range(200))
    assert len(toks) == 200
    print("Test 1 OK: Tokens are unique")

    # 2) HTML escape
    e = html_escape("<b>\"&</b>")
    assert "&lt;b&gt;&quot;&amp;&lt;/b&gt;" in e
    print("Test 2 OK: HTML escape works")

    # 3) Constant-time equals
    t = generate_token(8)
    assert validate_csrf(t, t)
    print("Test 3 OK: CSRF validation success")

    # 4) CSRF validation failure
    assert not validate_csrf(generate_token(8), generate_token(8))
    print("Test 4 OK: CSRF validation failure")

    # 5) Form builder contains token and fields
    form = build_settings_form("abc", "User_1", True)
    assert "_csrf" in form and "User_1" in form and "checkbox" in form
    print("Test 5 OK: Form builder works")

if __name__ == "__main__":
    run_tests()
    port = 8081
    httpd = HTTPServer(("127.0.0.1", port), App)
    print(f"Python server started at http://localhost:{port}")
    httpd.serve_forever()