import http.server
import socketserver
import json
import threading
import time
import urllib.request
from urllib.error import HTTPError

# Whitelist of allowed origins for CORS
ALLOWED_ORIGINS = {
    "http://localhost:3000",
    "https://safe.example.com"
}

PORT = 8081

class CorsApiHandler(http.server.SimpleHTTPRequestHandler):
    def handle_cors(self):
        """Sets CORS headers if the origin is allowed."""
        origin = self.headers.get('Origin')
        if origin in ALLOWED_ORIGINS:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With')
            return True
        return False

    def do_OPTIONS(self):
        """Handle preflight CORS requests."""
        if self.path == '/api/data':
            self.send_response(204)  # No Content
            self.handle_cors()
            self.end_headers()
        else:
            self.send_error(404, "Not Found")

    def do_GET(self):
        """Handle GET requests for the API endpoint."""
        if self.path == '/api/data':
            self.send_response(200)
            self.handle_cors()
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response_data = {"message": "Hello from Python CORS API!"}
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        else:
            # For simplicity, returning 404 for other paths
            self.send_error(404, 'Not Found')

def run_server():
    with socketserver.TCPServer(("", PORT), CorsApiHandler) as httpd:
        print(f"Python server started on port {PORT}")
        httpd.serve_forever()

def run_tests():
    """A simple client to demonstrate the 5 test cases"""
    server_url = f"http://localhost:{PORT}/api/data"

    def test_request(method, url, origin):
        try:
            headers = {}
            if origin:
                headers['Origin'] = origin
            if method == 'OPTIONS':
                headers['Access-Control-Request-Method'] = 'GET'
                headers['Access-Control-Request-Headers'] = 'Content-Type'

            req = urllib.request.Request(url, method=method, headers=headers)
            with urllib.request.urlopen(req) as response:
                print(f"Request: {method} {url} | Origin: {origin or 'none'}")
                print(f"Response Status: {response.status}")
                print(f"Access-Control-Allow-Origin Header: {response.getheader('Access-Control-Allow-Origin', 'Not present')}")
                body = response.read().decode('utf-8')
                if body:
                    print(f"Response Body: {body}")

        except HTTPError as e:
            print(f"Request: {method} {url} | Origin: {origin or 'none'}")
            print(f"Response Status: {e.code}")
            print(f"Access-Control-Allow-Origin Header: {e.headers.get('Access-Control-Allow-Origin', 'Not present')}")
        except Exception as e:
            print(f"Error during test request: {e}")

    print("\n--- Test Case 1: Preflight OPTIONS from allowed origin ---")
    test_request("OPTIONS", server_url, "https://safe.example.com")
    
    print("\n--- Test Case 2: GET from allowed origin ---")
    test_request("GET", server_url, "https://safe.example.com")

    print("\n--- Test Case 3: GET from disallowed origin ---")
    test_request("GET", server_url, "http://evil.com")

    print("\n--- Test Case 4: GET with no Origin header ---")
    test_request("GET", server_url, None)

    print("\n--- Test Case 5: GET request to a non-existent path ---")
    test_request("GET", f"http://localhost:{PORT}/other/path", "https://safe.example.com")

if __name__ == "__main__":
    # Run server in a separate thread so we can run tests
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Give the server a moment to start up
    time.sleep(1)
    
    print("Running tests...")
    run_tests()
    print("\nTests complete. Server is still running. Press Ctrl+C to stop.")
    
    # Keep main thread alive
    server_thread.join()