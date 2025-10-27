import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import urllib.request
import time

# Core logic function: accepts a URL string and returns (status_code, headers_dict, body_bytes)
def redirect_invalid_url(url_str: str):
    if not url_str:
        return 400, {"Content-Type": "text/plain; charset=utf-8"}, b"Missing URL"
    try:
        parsed = urllib.parse.urlparse(url_str)
        if not parsed.scheme or not parsed.netloc:
            return 400, {"Content-Type": "text/plain; charset=utf-8"}, b"Invalid URL"
        host = parsed.hostname or ""
        if host.lower() == "example.com":
            return 302, {"Location": url_str}, b""
        else:
            return 400, {"Content-Type": "text/plain; charset=utf-8"}, b"URL must be from example.com"
    except Exception:
        return 400, {"Content-Type": "text/plain; charset=utf-8"}, b"Invalid URL"

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        prefix = "/redirect/"
        if self.path.startswith(prefix):
            encoded = self.path[len(prefix):]
            decoded = urllib.parse.unquote(encoded)
            status, headers, body = redirect_invalid_url(decoded)
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Not Found")

def run_server(server):
    server.serve_forever()

def run_test(label, encoded_param):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    req_url = f"http://127.0.0.1:8081/redirect/{encoded_param}"
    try:
        resp = opener.open(req_url)
        status = getattr(resp, "status", resp.getcode())
        loc = resp.headers.get("Location")
        print(f"{label}: status={status}" + (f" location={loc}" if loc else ""))
        resp.read()
        resp.close()
    except urllib.error.HTTPError as e:
        status = e.code
        loc = e.headers.get("Location")
        print(f"{label}: status={status}" + (f" location={loc}" if loc else ""))

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8081), RedirectHandler)
    t = threading.Thread(target=run_server, args=(server,), daemon=True)
    t.start()
    print("Python server started at http://127.0.0.1:8081")
    time.sleep(0.3)

    tests = [
        urllib.parse.quote("https://example.com/"),
        urllib.parse.quote("http://example.com/blog"),
        urllib.parse.quote("https://evil.com/hack"),
        urllib.parse.quote("notaurl"),
        urllib.parse.quote("https://sub.example.com/")
    ]
    run_test("Test 1 (valid https example.com)", tests[0])
    run_test("Test 2 (valid http example.com)", tests[1])
    run_test("Test 3 (invalid other domain)", tests[2])
    run_test("Test 4 (invalid URL)", tests[3])
    run_test("Test 5 (subdomain not allowed)", tests[4])

    server.shutdown()
    t.join(timeout=1.0)
    print("Python tests complete.")