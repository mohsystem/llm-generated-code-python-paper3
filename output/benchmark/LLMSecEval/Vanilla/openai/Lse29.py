import re
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import urllib.parse
import urllib.request

ALLOW_PATTERN = re.compile(r'.*example\.com.*')

def matches_allowed(target: str) -> bool:
    if target is None:
        return False
    return bool(ALLOW_PATTERN.fullmatch(target))

def resolve_redirect(target: str) -> str:
    if target is None:
        target = ""
    return target if matches_allowed(target) else "/"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/go":
            qs = urllib.parse.parse_qs(parsed.query)
            target = qs.get("target", [None])[0]
            location = resolve_redirect(target)
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
        elif parsed.path == "/":
            body = b"Home"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass

def run_server(server):
    server.serve_forever()

if __name__ == "__main__":
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=run_server, args=(httpd,), daemon=True)
    t.start()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

        def http_error_302(self, req, fp, code, msg, headers):
            return fp

        http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    opener = urllib.request.build_opener(NoRedirect)

    tests = [
        "http://example.com/page",
        "https://sub.example.com",
        "http://evil.com/?next=example.com",
        "https://another.com/path",
        None  # missing
    ]

    for i, target in enumerate(tests, 1):
        if target is None:
            path = "/go"
        else:
            path = "/go?target=" + urllib.parse.quote(target, safe="")
        url = f"http://127.0.0.1:{port}{path}"
        req = urllib.request.Request(url, method="GET")
        try:
            resp = opener.open(req, timeout=3)
            # If we are here, opener did not follow; extract Location
            loc = resp.headers.get("Location")
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
        print(f"Test {i}: target={(target if target is not None else '(missing)')} -> redirect to {loc}")

    httpd.shutdown()