import http.server
import socketserver
import urllib.parse
import re
import sys
from typing import Optional

PORT = 8081
MAX_PARAM_LEN = 2048
MAX_QUERY_LEN = 4096
ALLOW_RE = re.compile(r"example\.com", re.IGNORECASE)

def decide_redirect(target: Optional[str]) -> str:
    if target is None:
        return "/"
    cleaned = target.replace("\r", "").replace("\n", "")
    if len(cleaned) > MAX_PARAM_LEN:
        return "/"
    if ALLOW_RE.search(cleaned):
        return cleaned
    return "/"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        try:
            parsed = urllib.parse.urlsplit(self.path)
            query = parsed.query
            if len(query) > MAX_QUERY_LEN:
                location = "/"
            else:
                params = urllib.parse.parse_qs(query, keep_blank_values=True, strict_parsing=False)
                target_vals = params.get("target")
                target = target_vals[0] if target_vals else None
                location = decide_redirect(target)
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Connection", "close")
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception:
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Connection", "close")
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, format: str, *args) -> None:
        # Quiet logging; avoid leaking user-controlled data
        sys.stderr.write("Request handled\n")

if __name__ == "__main__":
    # 5 test cases
    tests = [
        "http://example.com/path",
        "https://sub.example.com/",
        "http://evil.com/?q=example.com",
        "/local/path",
        "javascript:example.com"
    ]
    for t in tests:
        print(f"Input: {t} -> Redirect: {decide_redirect(t)}")

    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"Python server listening on http://127.0.0.1:{PORT} - try /?target=http://example.com")
        try:
            httpd.serve_forever()
        finally:
            httpd.server_close()