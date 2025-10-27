import html
import re
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

def build_info_page(username: str, email: str, ssn: str) -> str:
    username = (username or "")[:256]
    email = (email or "")[:256]
    ssn = ssn or ""
    safe_user = html.escape(username, quote=True)
    safe_email = html.escape(email, quote=True)
    last4 = _extract_last4(ssn)
    if not _is_valid_email(email) or not safe_user or not last4:
        return _html_page("Invalid input", "<p>Invalid or missing parameters.</p>")
    body = (
        "<h1>User Info</h1>"
        f"<ul><li>Username: {safe_user}</li>"
        f"<li>Email: {safe_email}</li>"
        f"<li>SSN (last 4): {last4}</li></ul>"
    )
    return _html_page("Info", body)

def _html_page(title: str, body: str) -> str:
    return f"<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>{html.escape(title)}</title></head><body>{body}</body></html>"

def _extract_last4(ssn: str) -> str:
    digits = [c for c in ssn if c.isdigit()]
    if len(digits) < 4:
        return ""
    return "".join(digits[-4:])

def _is_valid_email(email: str) -> bool:
    if not email or len(email) > 256:
        return False
    # Simplified safe email validation
    return re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) is not None

class InfoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/info":
            self._send(404, "text/plain; charset=UTF-8", b"Not Found")
            return
        qs = parse_qs(parsed.query or "")
        username = (qs.get("username", [""])[0])[:256]
        email = (qs.get("email", [""])[0])[:256]
        ssn = qs.get("ssn", [""])[0]
        if not username or not email or not ssn:
            body = _html_page("Bad Request", "<p>Missing required parameters: username, email, ssn.</p>").encode("utf-8")
            self._send(400, "text/html; charset=UTF-8", body)
            return
        body = build_info_page(username, email, ssn).encode("utf-8")
        status = 200 if b"Invalid input" not in body else 400
        self._send(status, "text/html; charset=UTF-8", body)

    def log_message(self, format, *args):
        # Avoid logging query strings to prevent leaking sensitive info
        pass

    def _send(self, status: int, ctype: str, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def start_server(port: int = 8081):
    srv = ThreadingHTTPServer(("127.0.0.1", port), InfoHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv

if __name__ == "__main__":
    # 5 test cases for core function
    print(build_info_page("alice", "alice@example.com", "123-45-6789"))
    print(build_info_page("<bob>", "bob@example.org", "0000"))
    print(build_info_page("charlie & co", "charlie@sub.example.com", "xxx-yy-9876"))
    print(build_info_page("dora", "invalid-email", "111-22-3333"))
    print(build_info_page("", "eve@example.net", "4444"))

    # Start the server
    start_server(8081)

    # Keep the main thread alive
    threading.Event().wait()