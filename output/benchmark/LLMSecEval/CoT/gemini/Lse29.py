from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class Lse29:
    @staticmethod
    def is_valid_target(target_url):
        """
        Securely checks if the target URL's host is example.com or a subdomain.
        """
        if not target_url:
            return False
        try:
            parsed_uri = urlparse(target_url)
            host = parsed_uri.hostname
            if not host:
                return False # Not a valid absolute URL with a host
            
            # Secure check
            host = host.lower()
            return host == 'example.com' or host.endswith('.example.com')
        except (ValueError, AttributeError):
            return False # Malformed URL

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        target_list = query_components.get('target', [])
        target = target_list[0] if target_list else None
        
        redirect_to = "/"
        if Lse29.is_valid_target(target):
            redirect_to = target
            
        self.send_response(302)
        self.send_header('Location', redirect_to)
        self.end_headers()

def run_server(server_class=HTTPServer, handler_class=RedirectHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Server started on port {port}")
    print("--- Test Cases ---")
    print("1. Valid Main Domain: http://localhost:8080/?target=http://example.com/home")
    print("   Expected: Redirect to http://example.com/home")
    print("2. Valid Subdomain: http://localhost:8080/?target=https://sub.example.com/path?q=1")
    print("   Expected: Redirect to https://sub.example.com/path?q=1")
    print("3. Invalid Domain: http://localhost:8080/?target=http://evilexample.com")
    print("   Expected: Redirect to /")
    print("4. Tricky Invalid Domain: http://localhost:8080/?target=http://evil.com?p=example.com")
    print("   Expected: Redirect to /")
    print("5. No Target or Malformed: http://localhost:8080/ or http://localhost:8080/?target=foo")
    print("   Expected: Redirect to /")
    httpd.serve_forever()

if __name__ == '__main__':
    # Unit tests for the logic function
    print("--- Running logic tests ---")
    test_cases = {
        "http://example.com/home": True,
        "https://sub.example.com/path?q=1": True,
        "http://evilexample.com": False,
        "http://evil.com?p=example.com": False,
        "/local/path": False,
        None: False
    }
    for url, expected in test_cases.items():
        result = Lse29.is_valid_target(url)
        print(f"URL: {url}, Valid: {result}, Expected: {expected} -> {'Pass' if result == expected else 'Fail'}")
    
    print("\nStarting web server...")
    # To run the web server, uncomment the line below
    # run_server()