import http.server
import socketserver
import threading
import uuid

SESSIONS = {}

def info(session: dict) -> str:
    username = session.get("username", "")
    email = session.get("email", "")
    ssn = session.get("ssn", "")
    return f"username: {username}; email: {email}; ssn: {ssn}"

def parse_cookie_sid(cookie_header: str):
    if not cookie_header:
        return None
    parts = [p.strip() for p in cookie_header.split(";")]
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            if k.strip() == "SID":
                return v.strip()
    return None

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/info":
            self.send_response(404)
            self.end_headers()
            return
        sid = parse_cookie_sid(self.headers.get("Cookie"))
        new_cookie = False
        if sid is None or sid not in SESSIONS:
            sid = uuid.uuid4().hex
            SESSIONS[sid] = {
                "username": "guest",
                "email": "guest@example.com",
                "ssn": "000-00-0000"
            }
            new_cookie = True

        body = info(SESSIONS[sid]).encode("utf-8")

        self.send_response(200)
        if new_cookie:
            self.send_header("Set-Cookie", f"SID={sid}; Path=/; HttpOnly")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def main():
    # 5 test cases for info()
    tests = [
        {"username": "alice", "email": "alice@example.com", "ssn": "111-22-3333"},
        {"username": "bob", "email": "bob@example.com", "ssn": "222-33-4444"},
        {"username": "carol", "email": "carol@example.com", "ssn": "333-44-5555"},
        {"username": "dave", "email": "dave@example.com", "ssn": "444-55-6666"},
        {"username": "eve", "email": "eve@example.com", "ssn": "555-66-7777"},
    ]
    for i, t in enumerate(tests, 1):
        print(f"Test {i}: {info(t)}")

    with socketserver.TCPServer(("", 8081), Handler) as httpd:
        print("Python server running on http://localhost:8081/info")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()