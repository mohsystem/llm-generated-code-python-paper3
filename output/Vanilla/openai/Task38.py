import html
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

def generate_form_page(title: str) -> str:
    safe_title = html.escape(title or "")
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>"
        + safe_title
        + "</title></head><body>"
        + "<h1>"
        + safe_title
        + "</h1>"
        + "<form method=\"POST\" action=\"/echo\">"
        + "<label>Enter a message: <input type=\"text\" name=\"message\" /></label>"
        + "<button type=\"submit\">Submit</button>"
        + "</form>"
        + "</body></html>"
    )

def generate_echo_page(message: str) -> str:
    safe_msg = html.escape(message or "")
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Echo Result</title></head>"
        "<body>"
        "<h1>Echo Result</h1>"
        "<p>You entered:</p>"
        "<div style=\"padding:8px;border:1px solid #ccc;background:#f9f9f9;white-space:pre-wrap;\">"
        + safe_msg
        + "</div>"
        "<p><a href=\"/\">Go back</a></p>"
        "</body></html>"
    )

class EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/echo"):
            # Allow GET /echo?message=...
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query or "", keep_blank_values=True)
            message = params.get("message", [""])[0]
            self._send_html(200, generate_echo_page(message))
        elif self.path == "/" or self.path.startswith("/?"):
            self._send_html(200, generate_form_page("Echo App"))
        else:
            self._send_html(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        if self.path == "/echo":
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            params = urllib.parse.parse_qs(body, keep_blank_values=True)
            message = params.get("message", [""])[0]
            self._send_html(200, generate_echo_page(message))
        else:
            self._send_html(404, "<h1>404 Not Found</h1>")

    def _send_html(self, status: int, content: str):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

def main():
    # 5 test cases for generation functions
    tests = [
        "Hello, Python!",
        "<script>alert('xss')</script>",
        "100% & safe?",
        "Multi\nLine\nInput",
        "Emoji: 🐍 مرحبا"
    ]
    for i, t in enumerate(tests, 1):
        html_out = generate_echo_page(t)
        print(f"Test {i} generated HTML length: {len(html_out)}")

    port = 8080
    server = HTTPServer(("0.0.0.0", port), EchoHandler)
    print(f"Python server running at http://localhost:{port} (Press Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()