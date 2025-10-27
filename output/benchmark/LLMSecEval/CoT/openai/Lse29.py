import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ALLOW_RE = re.compile(r'(?i)^https?://[^\s]*example\.com[^\s]*$')
MAX_LEN = 2048

def evaluate_redirect(target: str) -> str:
    if target is None:
        return "/"
    target = target.strip()
    if len(target) == 0 or len(target) > MAX_LEN:
        return "/"
    if any(ch in target for ch in ['\r', '\n']) or any(ord(ch) < 32 and ch not in ('\t',) for ch in target) or ord(target[-1]) == 127:
        return "/"
    if not ALLOW_RE.fullmatch(target):
        return "/"
    return target

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/go":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return
        qs = parse_qs(parsed.query)
        target = qs.get("target", [None])[0]
        location = evaluate_redirect(target)

        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(("Redirecting to: " + location + "\n").encode("utf-8"))

def run_server():
    httpd = HTTPServer(("127.0.0.1", 8081), RedirectHandler)
    print("Python server listening on http://127.0.0.1:8081/go?target=...")
    httpd.serve_forever()

if __name__ == "__main__":
    tests = [
        "https://example.com",
        "http://sub.example.com/path?x=1",
        "https://notexample.com",
        "https://example.com.evil.com/attack",
        "/local/path?target=https://example.com"
    ]
    for i, t in enumerate(tests, 1):
        print(f"Python Test {i}: input={t} -> redirect={evaluate_redirect(t)}")
    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    t.join()