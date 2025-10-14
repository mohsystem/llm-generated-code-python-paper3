import html
import http.server
import socketserver
from http import HTTPStatus
from urllib.parse import parse_qs
import secrets

MAX_INPUT_LEN = 500
MAX_BODY_BYTES = 4096
CSRF_COOKIE = "csrf"

def process_input(text: str) -> str:
    if text is None:
        return ""
    trimmed = text.strip()
    if len(trimmed) > MAX_INPUT_LEN:
        trimmed = trimmed[:MAX_INPUT_LEN]
    return html.escape(trimmed, quote=True)

def parse_cookies(header_value: str):
    cookies = {}
    if not header_value:
        return cookies
    parts = header_value.split(";")
    for part in parts:
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

def generate_token() -> str:
    return secrets.token_urlsafe(32)

class Handler(http.server.BaseHTTPRequestHandler):
    def _security_headers(self):
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")

    def _set_cookie(self, name, value, path="/", http_only=True, secure=True, same_site="Strict"):
        attrs = [f"{name}={value}", f"Path={path}"]
        if http_only:
            attrs.append("HttpOnly")
        if secure:
            attrs.append("Secure")
        if same_site:
            attrs.append(f"SameSite={same_site}")
        self.send_header("Set-Cookie", "; ".join(attrs))

    def do_GET(self):
        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            cookie_header = self.headers.get("Cookie")
            cookies = parse_cookies(cookie_header)
            csrf = cookies.get(CSRF_COOKIE)
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            if not csrf:
                csrf = generate_token()
                self._set_cookie(CSRF_COOKIE, csrf)
            self.send_header("Content-Type", "text/html; charset=UTF-8")
            self.end_headers()
            body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Echo</title></head>
<body>
<h1>Secure Echo</h1>
<form method="post" action="/submit">
<label for="msg">Enter text:</label>
<input id="msg" name="message" type="text" maxlength="{MAX_INPUT_LEN}" required>
<input type="hidden" name="csrf" value="{html.escape(csrf, quote=True)}">
<button type="submit">Submit</button>
</form>
</body></html>"""
            self.wfile.write(body.encode("utf-8"))
        except Exception:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self):
        if self.path != "/submit":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            ct = self.headers.get("Content-Type", "")
            if not ct.lower().startswith("application/x-www-form-urlencoded"):
                self.send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                return
            length_header = self.headers.get("Content-Length")
            if not length_header:
                self.send_error(HTTPStatus.LENGTH_REQUIRED)
                return
            try:
                length = int(length_header)
            except ValueError:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            if length < 0 or length > MAX_BODY_BYTES:
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            data = self.rfile.read(length).decode("utf-8", errors="strict")
            form = parse_qs(data, keep_blank_values=True)
            message = form.get("message", [""])[0]
            csrf_form = form.get("csrf", [""])[0]
            cookies = parse_cookies(self.headers.get("Cookie"))
            csrf_cookie = cookies.get(CSRF_COOKIE)
            if not csrf_cookie or csrf_cookie != csrf_form:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            safe = process_input(message)
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            self.send_header("Content-Type", "text/html; charset=UTF-8")
            self.end_headers()
            body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Echo Result</title></head>
<body>
<h1>Echoed back safely:</h1>
<p>{safe}</p>
<p><a href="/">Back</a></p>
</body></html>"""
            self.wfile.write(body.encode("utf-8"))
        except Exception:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

def run_server():
    # 5 test cases for process_input
    tests = [
        "<script>alert('x')</script>",
        "Hello, World!",
        "Quotes: \" ' & < >",
        "Unicode: Привет & こんにちは <b>bold</b>",
        "A" * 600
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i} -> {process_input(t)}")

    addr = ("127.0.0.1", 8081)
    with http.server.HTTPServer(addr, Handler) as httpd:
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()