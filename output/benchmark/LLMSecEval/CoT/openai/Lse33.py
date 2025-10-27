# Chain-of-Through in-code notes:
# 1) Understand: Provide a /go route with ?url= param; validate domain example.com and http/https; redirect or error.
# 2) Security: Prevent open redirects, header injection (CRLF), validate scheme and host.
# 3) Coding: Use urllib.parse for safe parsing.
# 4) Review: Ensure no untrusted header injection, strict domain check.
# 5) Output: Final handler uses validated URL only.

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading
import sys

def redirect_invalid_url(input_url: str):
    if not input_url:
        return ("error", "Missing URL")
    if "\r" in input_url or "\n" in input_url:
        return ("error", "Invalid characters in URL")
    try:
        u = urlparse(input_url.strip())
        if not u.scheme or not u.netloc:
            return ("error", "URL must include scheme and host")
        if u.scheme.lower() not in ("http", "https"):
            return ("error", "Only http and https schemes are allowed")
        host = u.hostname
        if host is None or host.lower() != "example.com":
            return ("error", "URL must have domain example.com")
        # Reconstruct ASCII-safe URL (urlparse returns already split parts; joining netloc preserves host)
        safe_url = input_url.strip()
        if "\r" in safe_url or "\n" in safe_url:
            return ("error", "Invalid URL")
        return ("redirect", safe_url)
    except Exception:
        return ("error", "Invalid URL format")

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Reduce noisy logging
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/go":
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return
        qs = parse_qs(parsed.query)
        url = qs.get("url", [None])[0]
        decision = redirect_invalid_url(url)
        if decision[0] == "redirect":
            self.send_response(302)
            self.send_header("Location", decision[1])
            self.end_headers()
        else:
            msg = decision[1].encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

def run_server():
    srv = HTTPServer(("localhost", 8081), Handler)
    print("Python server running on http://localhost:8081/go?url=...")
    srv.serve_forever()

if __name__ == "__main__":
    tests = [
        "https://example.com/path",
        "http://example.com",
        "https://sub.example.com/path",  # invalid: subdomain
        "ftp://example.com/resource",    # invalid: scheme
        "https://evil.com/path"          # invalid: host
    ]
    print("Python tests for redirect_invalid_url:")
    for t in tests:
        res = redirect_invalid_url(t)
        if res[0] == "redirect":
            print(f"OK redirect -> {res[1]}")
        else:
            print(f"ERROR -> {res[1]}")
    # Start server in a background thread so tests print first
    th = threading.Thread(target=run_server, daemon=True)
    th.start()
    # Keep main thread alive to serve
    try:
        th.join()
    except KeyboardInterrupt:
        sys.exit(0)