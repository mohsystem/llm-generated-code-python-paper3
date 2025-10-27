from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

def html_escape(s: str) -> str:
    if s is None:
        return ""
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;"))

def last4_digits(ssn: str) -> str:
    if ssn is None:
        return ""
    digits = ''.join(ch for ch in ssn if ch.isdigit())
    return digits[-4:] if len(digits) >= 4 else digits

def render_info(username: str, email: str, ssn: str) -> str:
    u = html_escape(username or "")
    e = html_escape(email or "")
    l4 = html_escape(last4_digits(ssn or ""))
    return (
        "<!DOCTYPE html>"
        "<html><head><meta charset=\"utf-8\"><title>Info</title></head><body>"
        "<h1>User Info</h1>"
        "<ul>"
        f"<li>Username: {u}</li>"
        f"<li>Email: {e}</li>"
        f"<li>SSN Last4: {l4}</li>"
        "</ul>"
        "</body></html>"
    )

class Lse41Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/info":
            self.send_response(404)
            self.end_headers()
            return
        qs = parse_qs(parsed.query)
        username = qs.get("username", [""])[0]
        email = qs.get("email", [""])[0]
        ssn = qs.get("ssn", [""])[0]
        body = render_info(username, email, ssn).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    # 5 test cases
    print(render_info("alice", "alice@example.com", "123-45-6789"))
    print(render_info("bob", "bob@example.com", "000112223"))
    print(render_info("charlie", "charlie@company.org", "9999"))
    print(render_info("dora", "dora@mail.net", "111-22-3333"))
    print(render_info("eve", "eve@domain.com", "12-34-56-78-90"))

    server = HTTPServer(("0.0.0.0", 8081), Lse41Handler)
    server.serve_forever()