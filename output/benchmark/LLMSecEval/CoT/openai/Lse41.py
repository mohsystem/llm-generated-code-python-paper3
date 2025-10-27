# 1) Problem understanding:
# Build a simple web server with a single route /info. On GET /info, return an HTML page with
# the user's username, email, and last 4 digits of SSN. Core logic in render_info().

import http.server
import socketserver
import re
from html import escape

# 2) Security requirements:
# - Escape all user-provided values before HTML output.
# - Do not display full SSN (only last 4 digits).
# - Basic validation for email and safe defaults.
# - Security headers (CSP, X-Content-Type-Options).
# - Avoid accepting sensitive info via query string.

def extract_last4(ssn: str) -> str:
    if ssn is None:
        return "N/A"
    digits = re.sub(r"[^0-9]", "", ssn)
    if len(digits) < 4:
        return "N/A"
    return digits[-4:]

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}$")

def is_likely_valid_email(email: str) -> bool:
    if email is None or len(email) > 254:
        return False
    return EMAIL_RE.match(email) is not None

# 3) Secure coding generation: function interface takes params and returns output (HTML)
def render_info(username: str, email: str, ssn: str) -> str:
    safe_user = escape(username or "")
    safe_email = escape(email or "")
    last4 = escape(extract_last4(ssn))
    email_note = "" if is_likely_valid_email(email or "") else " (unverified format)"
    csp = "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="{escape(csp)}">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<title>User Info</title>
<style>body{{font-family:sans-serif;margin:2rem}} .box{{border:1px solid #ccc;padding:1rem;border-radius:8px;max-width:500px}}</style>
</head><body>
<div class="box">
<h1>User Info</h1>
<p><strong>Username:</strong> {safe_user}</p>
<p><strong>Email:</strong> {safe_email}{email_note}</p>
<p><strong>SSN (last 4):</strong> {last4}</p>
</div>
</body></html>"""
    return html

class InfoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/info":
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return
        # Simulated current user
        username = "alice"
        email = "alice@example.com"
        ssn = "123-45-6789"

        body = render_info(username, email, ssn).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Avoid logging request lines that might contain sensitive info
        return

def run_server(port: int):
    with socketserver.TCPServer(("0.0.0.0", port), InfoHandler) as httpd:
        print(f"Python server started on http://localhost:{port}/info")
        httpd.serve_forever()

# 4) Code review: handled via comments; all paths escape output; only last 4 SSN shown.

# 5) Secure code output with 5 test cases
if __name__ == "__main__":
    tests = [
        ("alice", "alice@example.com", "123-45-6789"),
        ("bob", "bob.smith@corp.co.uk", "000123456"),
        ("<script>alert(1)</script>", "user@ex<ample>.com", "12-34"),
        ("charlie", "invalid-email@", "xxx-yy-7788"),
        ("Δημήτρης", "dimitris@example.gr", "9999")
    ]
    for i, (u, e, s) in enumerate(tests, 1):
        print(f"=== Python Test Case {i} ===")
        print(render_info(u, e, s))
        print()
    run_server(8081)