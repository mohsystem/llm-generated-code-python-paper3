import http.server
import socketserver
import re
from urllib.parse import urlparse, parse_qs

class Lse29(http.server.SimpleHTTPRequestHandler):
    # Secure regex to validate the target URL.
    # It ensures the protocol is http/https, the domain is example.com or a subdomain,
    # and prevents user-info pass-through (e.g., http://example.com@evil.com).
    URL_REGEX = re.compile(r"^https?://(?!.*@)([a-zA-Z0-9-]+\.)*example\.com(/.*)?$")

    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        target = query_components.get("target", [None])[0]

        redirect_to = "/"
        if target and self.URL_REGEX.match(target):
            redirect_to = target
        
        self.send_response(302)
        self.send_header('Location', redirect_to)
        self.end_headers()

def main():
    PORT = 8001
    with socketserver.TCPServer(("", PORT), Lse29) as httpd:
        print(f"Server started on port {PORT}")
        print("Test with URLs like:")
        print(f"http://localhost:{PORT}/?target=https://safe.example.com/path")
        print(f"http://localhost:{PORT}/?target=https://www.google.com")
        httpd.serve_forever()

if __name__ == "__main__":
    main()