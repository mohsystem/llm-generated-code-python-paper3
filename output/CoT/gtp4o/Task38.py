import http.server
import socketserver
import urllib.parse
import secrets
import threading
import sys

TOKENS = {}
LOCK = threading.Lock()
MAX_BODY = 4096
MAX_MSG = 200
ALLOWED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,;:!?@#()_-'\"")

def html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") \
            .replace("\"", "&quot;").replace("'", "&#x27;").replace("/", "&#x2F;")

def validate_message(raw: str):
    if raw is None:
        return None
    if len(raw) == 0 or len(raw) > MAX_MSG:
        return None
    for ch in raw:
        if ch in ("\r", "\n", "\t"):
            return None
        if ch not in ALLOWED:
            return None
    return raw

def csp():
    return "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'none'; img-src 'self'; base-uri 'none'; form-action 'self'"

def set_security_headers(handler):
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Content-Security-Policy", csp())

def get_cookie(headers, name):
    cookie = headers.get('Cookie')
    if not cookie:
        return None
    parts = cookie.split(';')
    for p in parts:
        if '=' in p:
            k, v = p.strip().split('=', 1)
            if k == name:
                return v
    return None

def parse_urlencoded(body: bytes):
    try:
        s = body.decode('utf-8', 'strict')
    except Exception:
        return {}
    parsed = urllib.parse.parse_qs(s, keep_blank_values=True, strict_parsing=False)
    return {k: v[0] if v else "" for k, v in parsed.items()}

def constant_time_eq(a: str, b: str) -> bool:
    if a is None or b is None or len(a) != len(b):
        return False
    res = 0
    for x, y in zip(a.encode(), b.encode()):
        res |= x ^ y
    return res == 0

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        sid = get_cookie(self.headers, "sid")
        if not sid or len(sid) < 16:
            sid = secrets.token_hex(16)
        csrf = secrets.token_hex(32)
        with LOCK:
            TOKENS[sid] = csrf

        self.send_response(200)
        set_security_headers(self)
        self.send_header("Set-Cookie", f"sid={sid}; HttpOnly; Path=/; SameSite=Strict")
        self.end_headers()
        html = f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp()}">
<title>Echo</title></head><body>
<h1>Secure Echo</h1>
<form method="POST" action="/echo">
<label>Message: <input type="text" name="message" maxlength="{MAX_MSG}"></label>
<input type="hidden" name="csrf" value="{csrf}">
<button type="submit">Send</button>
</form>
</body></html>"""
        self.wfile.write(html.encode('utf-8'))

    def do_POST(self):
        if self.path != "/echo":
            self.send_error(404)
            return
        ctype = self.headers.get('Content-Type', '')
        if not ctype.lower().startswith('application/x-www-form-urlencoded'):
            self.send_error(415, "Unsupported Media Type")
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except:
            length = 0
        if length > MAX_BODY:
            self.send_error(413, "Payload Too Large")
            return
        body = self.rfile.read(length)
        form = parse_urlencoded(body)
        sid = get_cookie(self.headers, "sid")
        got_csrf = form.get("csrf", "")
        expected = None
        with LOCK:
            if sid:
                expected = TOKENS.get(sid)
        if not sid or not expected or not constant_time_eq(expected, got_csrf):
            self.send_response(400)
            set_security_headers(self)
            self.end_headers()
            self.wfile.write(self.html_page("Invalid CSRF token.").encode('utf-8'))
            return

        raw = form.get("message", "")
        safe = validate_message(raw)
        if safe is None:
            self.send_response(400)
            set_security_headers(self)
            self.send_header("Set-Cookie", f"sid={sid}; HttpOnly; Path=/; SameSite=Strict")
            self.end_headers()
            self.wfile.write(self.html_page(f"Invalid input. Max {MAX_MSG} characters; basic punctuation/letters/digits only.").encode('utf-8'))
            return

        self.send_response(200)
        set_security_headers(self)
        self.send_header("Set-Cookie", f"sid={sid}; HttpOnly; Path=/; SameSite=Strict")
        self.end_headers()
        html = f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp()}">
<title>Echo</title></head><body>
<h1>Echo result</h1>
<p>You said: <strong>{html_escape(safe)}</strong></p>
<p><a href="/">Back</a></p>
</body></html>"""
        self.wfile.write(html.encode('utf-8'))

    def log_message(self, format, *args):
        # Reduce verbosity; still show essential logs to stdout
        sys.stdout.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format%args))

    def html_page(self, msg: str) -> str:
        return f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp()}">
<title>Echo</title></head><body>
<p>{html_escape(msg)}</p><p><a href="/">Back</a></p></body></html>"""

def run_server():
    with socketserver.TCPServer(("", 8081), Handler) as httpd:
        print("Python server running on http://localhost:8081/")
        httpd.serve_forever()

def _test():
    tests = [
        "<script>alert(1)</script>",
        "Hello, World!",
        "This_is-OK() #1!?",
        "A"*500,
        "Emoji 🙂"
    ]
    for t in tests:
        v = validate_message(t)
        print("Test:", t[:30] + ("..." if len(t) > 30 else ""), "=>", "OK:" + html_escape(v) if v else "INVALID")

if __name__ == "__main__":
    _test()
    run_server()