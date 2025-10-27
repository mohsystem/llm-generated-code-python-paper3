import http.server
import socketserver
import json
import cgi

# In a real application, use a robust framework like Flask or Django.
# This example uses Python's built-in http.server for simplicity.

class SecureNameHandler(http.server.BaseHTTPRequestHandler):
    """
    A secure handler for processing POST requests to check for a 'name' field.
    """
    def do_POST(self):
        # Security: Check Content-Type header to ensure it's what we expect.
        content_type, _ = cgi.parse_header(self.headers.get('Content-Type', ''))
        if content_type != 'application/json':
            self.send_error(415, "Unsupported Media Type: Please use application/json")
            return

        # Security: Check Content-Length to prevent denial-of-service from large payloads.
        try:
            content_length = int(self.headers['Content-Length'])
            if content_length > 4096: # Limit payload size
                self.send_error(413, "Payload Too Large")
                return
            body = self.rfile.read(content_length)
        except (TypeError, ValueError):
            self.send_error(400, "Bad Request: Invalid Content-Length")
            return

        try:
            # Using json.loads is generally safe against injection attacks.
            data = json.loads(body.decode('utf-8'))
            if not isinstance(data, dict):
                 raise ValueError("Payload must be a JSON object.")
                 
            name = data.get('name')

            if name is not None:
                # Security: Returning as text/plain is safer against XSS.
                # If this were to be rendered in HTML, it would need escaping (e.g., html.escape(name)).
                self.send_response(200)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(str(name).encode('utf-8'))
            else:
                self.send_response(400)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(b"Field 'name' not found.")
        
        except (json.JSONDecodeError, ValueError) as e:
            self.send_error(400, f"Bad Request: Invalid JSON payload. {e}")
        except Exception:
            self.send_error(500, "Internal Server Error")

    def do_GET(self):
        # Security: Disallow GET requests for this endpoint.
        self.send_error(405, "Method Not Allowed: Please use POST.")


def run_server(port=8081):
    """Starts the HTTP server."""
    handler = SecureNameHandler
    # Using ThreadingTCPServer to handle concurrent requests
    with socketserver.ThreadingTCPServer(("", port), handler) as httpd:
        print(f"Server started on port {port}")
        print("Use a tool like curl to test the 5 cases below:")
        print("---")
        
        print("Test Case 1: Valid name")
        print(f"curl -X POST -H \"Content-Type: application/json\" -d '{{\"user\": \"guest\", \"name\": \"Alice\"}}' http://localhost:{port}")
        
        print("\nTest Case 2: No 'name' field")
        print(f"curl -X POST -H \"Content-Type: application/json\" -d '{{\"user\": \"guest\", \"id\": 123}}' http://localhost:{port}")

        print("\nTest Case 3: Empty payload")
        print(f"curl -X POST -H \"Content-Type: application/json\" -d '' http://localhost:{port}")
        
        print("\nTest Case 4: Name with special characters (should be returned as is for text/plain)")
        print(f"curl -X POST -H \"Content-Type: application/json\" -d '{{\"name\": \"Bob <script>alert(1)</script>\"}}' http://localhost:{port}")

        print("\nTest Case 5: Use GET method (should be rejected)")
        print(f"curl -X GET http://localhost:{port}")
        
        httpd.serve_forever()

if __name__ == "__main__":
    # Test cases are demonstrated via curl commands printed to the console.
    # The main function runs the server to allow for this testing.
    run_server()