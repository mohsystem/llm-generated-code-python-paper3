import http.server
import socketserver
import urllib.parse
import sys
from typing import Tuple, Dict

MAX_URL_LENGTH = 2048
MAX_QUERY_LENGTH = 4096

def redirect_invalid_url(url: str) -> Tuple[int, Dict[str, str], str]:
    """
    Returns: (status_code, headers, body)
    302 with Location header if valid; 400 with error body otherwise.
    """
    if url is None:
        return 400, {}, "Invalid URL"
    trimmed = url.strip()
    if not trimmed or len(trimmed) > MAX_URL_LENGTH:
        return 400, {}, "Invalid URL"
    if "\r" in trimmed or "\n" in trimmed:
        return 400, {}, "Invalid URL"
    try:
        parts = urllib.parse.urlsplit(trimmed)
    except Exception:
        return 400, {}, "Invalid URL"
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return 400, {}, "Invalid URL"
    netloc = parts.netloc
    if not netloc:
        return 400, {}, "Invalid URL"
    if '@' in netloc:
        return 400, {}, "Invalid URL"
    # Strip port if present
    host = netloc.split(':', 1)[0].lower()
    if host != "example.com":
        return 400, {}, "Invalid URL"
    safe_location = trimmed.replace("\r", "").replace("\n", "")
    return 302, {"Location": safe_location}, ""

class GoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path != "/go":
                self.send_response(404)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Not Found")
                return
            raw_query = parsed.query or ""
            if len(raw_query) == 0 or len(raw_query) > MAX_QUERY_LENGTH:
                self._send_invalid()
                return
            qs = urllib.parse.parse_qs(raw_query, strict_parsing=False, keep_blank_values=True, max_num_fields=20)
            vals = qs.get("url")
            if not vals:
                self._send_invalid()
                return
            url_param = vals[0]
            status, headers, body = redirect_invalid_url(url_param)
            if status == 302:
                self.send_response(302)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
            else:
                self._send_invalid()
        except Exception:
            self._send_invalid()

    def log_message(self, format, *args):
        # Reduce logging
        return

    def _send_invalid(self):
        msg = "Invalid URL".encode("utf-8")
        self.send_response(400)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg)

def start_server(port: int) -> None:
    with socketserver.TCPServer(("127.0.0.1", port), GoHandler) as httpd:
        print(f"Server on http://127.0.0.1:{port}/go?url=http%3A%2F%2Fexample.com%2F")
        httpd.serve_forever()

if __name__ == "__main__":
    # 5 test cases
    tests = [
        "http://example.com/",
        "https://example.com/path?x=1",
        "https://sub.example.com/",
        "ftp://example.com/",
        "https://example.com/\r\nX: a"
    ]
    for t in tests:
        code, headers, body = redirect_invalid_url(t)
        if code == 302:
            print(f"OK 302 -> {headers.get('Location','')}")
        else:
            print(f"ERR {code}")

    # Optionally run server: python script.py serve
    if len(sys.argv) > 1 and sys.argv[1].lower() == "serve":
        start_server(8081)