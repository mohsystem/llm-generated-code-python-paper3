#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from typing import Dict
import html
import sys

HOST = "127.0.0.1"
PORT = 8000
MAX_BODY = 4096
MAX_MESSAGE_LEN = 200

def sanitize_input(value: str, max_len: int = MAX_MESSAGE_LEN) -> str:
    if value is None:
        return ""
    v = value.strip()
    # remove most control chars except , \r, \t
    v = "".join(ch for ch in v if (ch in "\n\r\t") or (not ch.isprintable() and ch not in "\n\r\t") is False)
    if len(v) > max_len:
        v = v[:max_len]
    return v

def escape_html(value: str) -> str:
    return html.escape(value, quote=True)

def render_page(result_html: str | None) -> bytes:
    body = []
    body.append("<!DOCTYPE html><html lang=\"en\"><head>")
    body.append("<meta charset=\"UTF-8\">")
    body.append("<meta http-equiv=\"X-Content-Type-Options\" content=\"nosniff\">")
    body.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
    body.append("<title>Echo App</title>")
    body.append("<style>body{font-family:sans-serif;margin:2rem;}input[type=text]{width:300px;max-width:90%;padding:.4rem;}button{padding:.4rem .8rem;margin-left:.5rem;} .result{margin-top:1rem;padding:.8rem;background:#f4f6f8;border:1px solid #dfe3e8;border-radius:6px;}</style>")
    body.append("</head><body>")
    body.append("<h1>Echo App</h1>")
    body.append("<form method=\"post\" action=\"/submit\" autocomplete=\"off\">")
    body.append("<label for=\"message\">Message (max 200 chars):</label><br>")
    body.append("<input id=\"message\" name=\"message\" type=\"text\" maxlength=\"200\" required>")
    body.append("<button type=\"submit\">Send</button>")
    body.append("</form>")
    if result_html:
        body.append(f"<div class=\"result\">{result_html}</div>")
    body.append("</body></html>")
    return "".join(body).encode("utf-8")

class SafeHandler(BaseHTTPRequestHandler):
    server_version = "SafeEcho/1.0"

    def log_message(self, format: str, *args) -> None:
        # Avoid logging potentially untrusted input
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format % tuple("..." for _ in args)))

    def do_GET(self) -> None:
        if self.path != "/" and self.path != "/index.html":
            self.send_error(404, "Not Found")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; form-action 'self'")
        body = render_page(None)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/submit":
            self.send_error(404, "Not Found")
            return
        ctype = self.headers.get("Content-Type", "")
        if not ctype.lower().startswith("application/x-www-form-urlencoded"):
            self.send_error(400, "Unsupported Content-Type")
            return
        try:
            clen = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400, "Bad Content-Length")
            return
        if clen < 0 or clen > MAX_BODY:
            self.send_error(413, "Payload Too Large")
            return
        body = self.rfile.read(clen)
        if len(body) != clen:
            self.send_error(400, "Bad Request")
            return
        params: Dict[str, list[str]] = parse_qs(body.decode("utf-8", errors="strict"), keep_blank_values=True, strict_parsing=False, max_num_fields=10)
        message_raw = params.get("message", [""])[0]
        sanitized = sanitize_input(message_raw, MAX_MESSAGE_LEN)
        escaped = escape_html(sanitized)
        result = f"You submitted: <strong>{escaped}</strong>"
        page = render_page(result)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; form-action 'self'")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)

def run_tests() -> None:
    tests = [
        "<script>alert(1)</script>",
        "Hello & Goodbye",
        "   trims   ",
        "A" * 500,
        "Controls\u0001\u0002removed"
    ]
    for i, t in enumerate(tests, 1):
        s = sanitize_input(t)
        e = escape_html(s)
        print(f"Test {i}: input=[{t}] sanitized=[{s}] escaped=[{e}]")

def main() -> None:
    run_tests()
    httpd = HTTPServer((HOST, PORT), SafeHandler)
    print(f"Server started on http://{HOST}:{PORT}/")
    httpd.serve_forever()

if __name__ == "__main__":
    main()