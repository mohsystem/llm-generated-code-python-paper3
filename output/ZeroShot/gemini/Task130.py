import http.server
import socketserver
import json

class CorsApiHandler(http.server.SimpleHTTPRequestHandler):
    """
    A simple HTTP request handler that implements CORS for the /api/data endpoint.
    """
    def _set_cors_headers(self):
        """Send CORS headers."""
        # For enhanced security, restrict the origin to your frontend's domain instead of "*".
        # self.send_header("Access-Control-Allow-Origin", "https://your-frontend-domain.com")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.send_header("Access-Control-Max-Age", "86400") # Cache preflight for 1 day

    def do_OPTIONS(self):
        """Handle preflight CORS requests."""
        if self.path == '/api/data':
            self.send_response(204) # No Content
            self._set_cors_headers()
            self.end_headers()
        else:
            self.send_error(404, "Not Found")

    def do_GET(self):
        """Handle GET requests for the API endpoint."""
        if self.path == '/api/data':
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = {"message": "Hello from a CORS-enabled Python API!"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        """Handle other methods like POST, which are not allowed for this API."""
        if self.path == '/api/data':
            self.send_response(405) # Method Not Allowed
            self._set_cors_headers() # Send CORS headers even on errors for consistency
            self.send_header("Content-type", "application/json")
            self.end_headers()
            response = {"error": "405 Method Not Allowed"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.send_error(404, "Not Found")

def run_server(port=8080, handler=CorsApiHandler):
    """Starts the HTTP server."""
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"Python server started on port {port}...")
        print(f"API endpoint available at http://localhost:{port}/api/data")
        httpd.serve_forever()

def run_tests(port=8080):
    """Prints instructions for testing the server."""
    print("\n--- How to Test ---")
    print("Run the following cURL commands in a separate terminal:")
    print("1. Test Preflight (OPTIONS) request for CORS:")
    print(f"   curl -i -X OPTIONS http://localhost:{port}/api/data -H \"Origin: http://example.com\" -H \"Access-Control-Request-Method: GET\"")
    print("\n2. Test actual (GET) request from a simulated foreign origin:")
    print(f"   curl -i -X GET http://localhost:{port}/api/data -H \"Origin: http://example.com\"")
    print("\n3. Test GET request without an Origin header (like a server-to-server call):")
    print(f"   curl -i http://localhost:{port}/api/data")
    print("\n4. Test a non-existent API endpoint:")
    print(f"   curl -i http://localhost:{port}/api/other")
    print("\n5. Test a disallowed method (e.g., POST) on the API endpoint:")
    print(f"   curl -i -X POST http://localhost:{port}/api/data -H \"Origin: http://example.com\"")
    print("--------------------\n")

if __name__ == "__main__":
    PORT = 8080
    run_tests(PORT)
    try:
        run_server(port=PORT)
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    except OSError as e:
        print(f"\nCould not start server on port {PORT}: {e}")