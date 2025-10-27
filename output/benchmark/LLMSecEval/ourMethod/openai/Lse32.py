import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse
import sys
import time

MAX_URL_LEN = 2048

class RedirectResult:
    def __init__(self, valid: bool, message: str, target: str | None):
        self.valid = valid
        self.message = message
        self.target = target

def redirect_invalid_url(raw_url: str) -> RedirectResult:
    if raw_url is None:
        return RedirectResult(False, "Invalid URL", None)
    if len(raw_url) == 0 or len(raw_url) > MAX_URL_LEN:
        return RedirectResult(False, "Invalid URL", None)
    # Reject control chars
    if any(ord(c) < 32 or ord(c) == 127 for c in raw_url):
        return RedirectResult(False, "Invalid URL", None)
    try:
        pu = urlparse(raw_url)
    except Exception:
        return RedirectResult(False, "Invalid URL", None)
    if pu.scheme.lower() not in ("http", "https"):
        return RedirectResult(False, "Invalid URL", None)
    # Reject userinfo
    if "@" in pu.netloc:
        return RedirectResult(False, "Invalid URL", None)
    # Hostname attribute normalizes to lower
    if pu.hostname is None or pu.hostname.lower() != "example.com":
        return RedirectResult(False, "Invalid URL", None)
    return RedirectResult(True, "OK", raw_url)

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            prefix = "/redirect/"
            if not self.path.startswith(prefix):
                self.send_response(404)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Not Found\n")
                return
            encoded = self.path[len(prefix):]
            if not encoded:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Invalid URL\n")
                return
            try:
                decoded = unquote(encoded, errors="strict")
            except Exception:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Invalid URL\n")
                return
            res = redirect_invalid_url(decoded)
            if not res.valid:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Invalid URL\n")
                return
            self.send_response(302)
            self.send_header("Location", res.target)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Redirecting...\n")
        except Exception:
            try:
                self.send_response(500)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Server Error\n")
            except Exception:
                pass

def run_server(server):
    with server:
        server.serve_forever()

def main():
    # Start server
    server = ThreadingHTTPServer(("127.0.0.1", 8081), RedirectHandler)
    t = threading.Thread(target=run_server, args=(server,), daemon=True)
    t.start()
    print("Server listening on http://127.0.0.1:8081")

    # Five test cases for the function
    tests = [
        "https://example.com/path",
        "http://example.com",
        "https://evil.com",
        "https://example.com:8443/",
        "https://user@example.com/"
    ]
    for url in tests:
        r = redirect_invalid_url(url)
        if r.valid:
            print(f"[VALID] {url} -> {r.target}")
        else:
            print(f"[INVALID] {url} -> {r.message}")

    # Give some time, then shutdown to exit cleanly
    time.sleep(0.1)
    server.shutdown()
    t.join(timeout=2)

if __name__ == "__main__":
    main()