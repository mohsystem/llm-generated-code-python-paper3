# Chain-of-Through (concise):
# 1) Implement /redirect/<url>, redirect only to example.com.
# 2) Security: validate scheme/host, reject CR/LF, limit length.
# 3) Secure code: urllib.parse for robust parsing, safe headers.
# 4) Review: simple, minimal, strong checks.
# 5) Output: final implementation with tests.

import http.server
import socketserver
import threading
from urllib.parse import urlparse
from typing import Dict, Any

MAX_URL_LEN = 2048

class Result:
    def __init__(self, status: int, redirect: bool, location: str = None, body: str = None):
        self.status = status
        self.redirect = redirect
        self.location = location
        self.body = body

def _has_crlf(s: str) -> bool:
    return any(ch in ('\r', '\n') for ch in s)

def _percent_decode(segment: str) -> str:
    # decode %XX, keep '+'
    out = bytearray()
    i = 0
    bs = segment.encode('utf-8', 'surrogatepass')
    # Work with text, simpler approach:
    s = segment
    length = len(s)
    while i < length:
        c = s[i]
        if c == '%' and i + 2 < length:
            try:
                byte = int(s[i+1:i+3], 16)
                out.append(byte)
                i += 3
            except ValueError:
                out.extend(c.encode('utf-8'))
                i += 1
        else:
            out.extend(c.encode('utf-8'))
            i += 1
    return out.decode('utf-8', 'strict')

def redirect_invalid_url(input_url: str) -> Result:
    if input_url is None:
        return Result(400, False, None, "Invalid or disallowed URL")
    url = input_url.strip()
    if not url or len(url) > MAX_URL_LEN or _has_crlf(url):
        return Result(400, False, None, "Invalid or disallowed URL")
    try:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return Result(400, False, None, "Invalid or disallowed URL")
        scheme = p.scheme.lower()
        if scheme not in ("http", "https"):
            return Result(400, False, None, "Invalid or disallowed URL")
        # hostname is lowercased by urlparse
        host = p.hostname
        if host is None or host.lower() != "example.com":
            return Result(400, False, None, "Invalid or disallowed URL")
        # Rebuild URL safely (keep original path/query/fragment)
        location = f"{scheme}://{host}"
        if p.port:
            location += f":{p.port}"
        location += p.path or ""
        if p.query:
            location += "?" + p.query
        if p.fragment:
            location += "#" + p.fragment
        if _has_crlf(location):
            return Result(400, False, None, "Invalid or disallowed URL")
        return Result(302, True, location, "Redirecting...")
    except Exception:
        return Result(400, False, None, "Invalid or disallowed URL")

class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            path = self.path  # includes percent-encoding
            prefix = "/redirect/"
            if not path.startswith(prefix):
                if path == "/redirect":
                    self.send_response(400)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b"Invalid or disallowed URL")
                    return
                self.send_response(404)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Not Found")
                return
            encoded = path[len(prefix):]
            decoded_url = _percent_decode(encoded)
            res = redirect_invalid_url(decoded_url)
            self.send_response(res.status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            if res.redirect and res.location:
                self.send_header("Location", res.location)
            self.end_headers()
            if res.body:
                self.wfile.write(res.body.encode("utf-8"))
        finally:
            pass

def _run_server():
    with socketserver.TCPServer(("0.0.0.0", 8081), RedirectHandler) as httpd:
        print("Python server listening on http://127.0.0.1:8081")
        httpd.serve_forever()

if __name__ == "__main__":
    # 5 test cases
    tests = [
        "https://example.com/path?q=1",
        "http://example.com",
        "https://notexample.com/bad",
        "javascript:alert(1)",
        "https://example.com:443/ok#frag",
    ]
    for t in tests:
        r = redirect_invalid_url(t)
        print(f"Test: {t} => status={r.status}, redirect={r.redirect}" + (f", location={r.location}" if r.location else ""))

    # Start server in the main thread
    _run_server()