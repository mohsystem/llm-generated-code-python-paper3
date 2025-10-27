import http.server
import socketserver
import threading
import time
import urllib.request
from typing import Dict, Optional

class Lse42:
    SESSIONS: Dict[str, Dict[str, str]] = {}

    @staticmethod
    def sanitize_user_or_email(v: Optional[str], max_len: int) -> str:
        if v is None:
            return ""
        out = []
        for c in v:
            if len(out) >= max_len:
                break
            if c.isalnum() or c in ['@', '.', '-', '_', '+', ' ']:
                out.append(c)
        return ''.join(out)

    @staticmethod
    def sanitize_ssn(v: Optional[str], max_len: int) -> str:
        if v is None:
            return ""
        out = []
        for c in v:
            if len(out) >= max_len:
                break
            if c.isdigit() or c == '-':
                out.append(c)
        return ''.join(out)

    @staticmethod
    def info(session: Optional[Dict[str, str]]) -> str:
        if session is None:
            return "Unauthorized"
        u = Lse42.sanitize_user_or_email(session.get('username'), 100)
        e = Lse42.sanitize_user_or_email(session.get('email'), 254)
        s = Lse42.sanitize_ssn(session.get('ssn'), 11)
        return f"username={u}; email={e}; ssn={s}"

class InfoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path != '/info':
                self.send_response(404)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Content-Security-Policy', "default-src 'none'")
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(b'Not Found')
                return
            sid = self._parse_sid()
            sess = Lse42.SESSIONS.get(sid) if sid else None
            if not sess:
                self.send_response(401)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Content-Security-Policy', "default-src 'none'")
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(b'Unauthorized')
                return
            body = Lse42.info(sess).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'")
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
        finally:
            pass

    def log_message(self, format, *args):
        # Avoid logging sensitive data
        return

    def _parse_sid(self) -> Optional[str]:
        cookie = self.headers.get('Cookie')
        if not cookie:
            return None
        parts = [p.strip() for p in cookie.split(';')]
        for p in parts:
            if p.startswith('SID='):
                return p[4:]
        return None

def run_server():
    with socketserver.TCPServer(("127.0.0.1", 18081), InfoHandler) as httpd:
        httpd.serve_forever()

def http_get(url: str, cookie: Optional[str]) -> str:
    req = urllib.request.Request(url, method='GET', headers={'Accept': 'text/plain'})
    if cookie:
        req.add_header('Cookie', cookie)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            code = resp.getcode()
            body = resp.read().decode('utf-8', errors='replace')
            return f"{code}:{body}"
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        return f"{e.code}:{body}"

def mask_ssn(body: str) -> str:
    import re
    return re.sub(r"\b(\d{3})-(\d{2})-(\d{4})\b", r"***-**-\3", body)

if __name__ == "__main__":
    # Populate sessions
    Lse42.SESSIONS["sid1"] = {"username": "alice", "email": "alice@example.com", "ssn": "123-45-6789"}
    Lse42.SESSIONS["sid2"] = {"username": "bob", "email": "bob.smith+dev@example.org", "ssn": "000-12-3456"}
    Lse42.SESSIONS["sid3"] = {"username": "charlie_ze", "email": "charlie.ze@example.net", "ssn": "999-99-9999"}
    Lse42.SESSIONS["sid4"] = {"username": "dana-j", "email": "dana-j@example.co", "ssn": "321-54-9876"}

    # Start server in background
    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(0.2)

    tests = ["SID=sid1", "SID=sid2", "SID=sid3", "SID=sid4", "SID=invalid"]
    for i, ck in enumerate(tests, 1):
        res = http_get("http://127.0.0.1:18081/info", ck)
        print(f"Test {i} -> {mask_ssn(res)}")