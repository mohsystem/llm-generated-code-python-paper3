import http.server
import socketserver
import secrets
import html
import re
import datetime

PORT = 5000
SESSIONS = {}

def last4_digits(ssn: str) -> str:
    if ssn is None:
        return "****"
    digits = re.sub(r'[^0-9]', '', ssn)
    if len(digits) < 4:
        return "****"
    return digits[-4:]

def render_info_page(username: str, email: str, ssn: str) -> str:
    safe_user = html.escape(username or "")
    safe_email = html.escape(email or "")
    l4 = html.escape(last4_digits(ssn))
    now = html.escape(datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT"))
    return (
        "<!doctype html><html lang=\"en\"><head>"
        "<meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>Info</title>"
        "</head><body>"
        "<h1>Account Info</h1>"
        f"<ul><li>Username: {safe_user}</li>"
        f"<li>Email: {safe_email}</li>"
        f"<li>SSN (last 4): {l4}</li></ul>"
        f"<p>Generated at {now}</p>"
        "</body></html>"
    )

class Lse40Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/info":
            self.send_error(404, "Not Found")
            return
        # Retrieve or create session
        sid = self._get_cookie("SID")
        new_session = False
        if sid is None or not re.fullmatch(r"[A-Fa-f0-9]{64}", sid) or sid not in SESSIONS:
            sid = secrets.token_hex(32)
            # Demo values; in real apps, set after authentication
            SESSIONS[sid] = {
                "username": "demo_user",
                "email": "demo.user@example.com",
                "ssn": "111-22-3333",
            }
            new_session = True

        session = SESSIONS.get(sid)
        if session is None:
            body = html.escape("Session not found.")
        else:
            body = render_info_page(session.get("username"), session.get("email"), session.get("ssn"))

        body_bytes = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if new_session:
            cookie = f"SID={sid}; Path=/; HttpOnly; SameSite=Strict; Secure"
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def log_message(self, format, *args):
        # Reduce server header leakage by suppressing logs to stdout
        pass

    def _get_cookie(self, name: str):
        cookie = self.headers.get("Cookie")
        if not cookie:
            return None
        try:
            parts = [p.strip() for p in cookie.split(";")]
            for p in parts:
                if "=" in p:
                    k, v = p.split("=", 1)
                    if k.strip() == name:
                        return v.strip()
        except Exception:
            return None
        return None

def main():
    # 5 test cases for render_info_page
    print(render_info_page("alice", "alice@example.com", "123-45-6789"))
    print(render_info_page("bob<script>", "bob@example.com", "000-00-0001"))
    print(render_info_page("carol", "carol+test@example.com", "9999"))
    print(render_info_page("dave", "dave.o'reilly@example.com", "12-3456"))
    print(render_info_page("eve", "eve@example.com", "abcd-ef-ghij"))

    with socketserver.TCPServer(("127.0.0.1", PORT), Lse40Handler) as httpd:
        print(f"Python server started on http://127.0.0.1:{PORT}/info")
        httpd.serve_forever()

if __name__ == "__main__":
    main()