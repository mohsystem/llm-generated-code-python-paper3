import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit, parse_qs, unquote_plus
import sys

def redirect_invalid_url(url: str):
    if url is None:
        return (False, "Missing URL parameter.")
    if len(url) > 2048:
        return (False, "URL too long.")
    if "\r" in url or "\n" in url:
        return (False, "Invalid characters in URL.")

    try:
        parts = urlsplit(url)
        if not parts.scheme:
            return (False, "URL must include a scheme.")
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            return (False, "Unsupported scheme.")

        # Disallow userinfo for safety
        if parts.username is not None or parts.password is not None:
            return (False, "Userinfo not allowed in URL.")

        host = parts.hostname
        if host is None:
            return (False, "Invalid host.")
        if host.lower() != "example.com":
            return (False, "URL must be on example.com.")

        # Normalize path
        path = parts.path if parts.path else "/"
        # Rebuild normalized URL
        netloc = host.lower()
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        query = parts.query
        fragment = parts.fragment
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        if fragment:
            normalized += f"#{fragment}"
        return (True, normalized)
    except Exception:
        return (False, "Malformed URL.")

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split('?', 1)[0] != "/go":
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        qs = ""
        if "?" in self.path:
            qs = self.path.split("?", 1)[1]
        params = parse_qs(qs, keep_blank_values=True)
        raw_url = params.get("url", [None])[0]
        if raw_url is not None:
            raw_url = unquote_plus(raw_url)
        ok, val = redirect_invalid_url(raw_url)
        if ok:
            self.send_response(302)
            self.send_header("Location", val)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
        else:
            msg = f"Error: {val}".encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

def start_server(port: int):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.serve_forever()

if __name__ == "__main__":
    # Start server in background
    t = threading.Thread(target=start_server, args=(8081,), daemon=True)
    t.start()

    # Five test cases
    tests = [
        "https://example.com/",
        "http://example.com/path?x=1",
        "https://sub.example.com/",
        "https://example.com.evil.com/",
        "https://example.com:8080/path#frag",
    ]
    for u in tests:
        ok, v = redirect_invalid_url(u)
        if ok:
            print(f"OK -> {v}")
        else:
            print(f"ERR -> {v}")

    print("Python server running on http://127.0.0.1:8081/go?url=<encoded_url>")
    try:
        t.join()
    except KeyboardInterrupt:
        sys.exit(0)