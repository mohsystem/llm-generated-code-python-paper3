from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import sys

# Security: Maximum payload size to prevent DoS attacks
MAX_PAYLOAD_SIZE = 10240  # 10KB limit


def process_payload(payload):
    """
    Process the payload parameter and extract the name value.

    Security measures:
    - Input validation for size and type
    - Safe JSON parsing without code execution
    - Output sanitization
    """
    if payload is None or len(payload) == 0:
        return json.dumps({"error": "Invalid input"})

    if len(payload) > MAX_PAYLOAD_SIZE:
        return json.dumps({"error": "Payload too large"})

    try:
        # Safe JSON parsing
        payload_dict = json.loads(payload)

        if not isinstance(payload_dict, dict):
            return json.dumps({"error": "Invalid payload format"})

        if "name" not in payload_dict:
            return json.dumps({"error": "Missing name field"})

        name = payload_dict.get("name")

        if not isinstance(name, str):
            return json.dumps({"error": "Invalid name type"})

        # Output is safely encoded via json.dumps
        return json.dumps({"name": name})

    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON format"})

    except Exception:
        return json.dumps({"error": "Processing error"})


class ApiHandler(BaseHTTPRequestHandler):
    """HTTP request handler for /api endpoint"""

    def do_GET(self):
        """Handle GET requests to /api endpoint"""
        parsed_path = urlparse(self.path)

        if parsed_path.path != "/api":
            self.send_error(404)
            return

        query_params = parse_qs(parsed_path.query)
        payload = query_params.get("payload", [None])[0]

        result = process_payload(payload)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(result.encode("utf-8"))

    def log_message(self, format, *args):
        """Override to prevent logging sensitive data"""
        pass


def main():
    """Main function to start the web server and run test cases"""
    server_address = ("", 8000)
    httpd = HTTPServer(server_address, ApiHandler)

    print("Server started on port 8000")
    print("\nTest cases:")
    print("1. Valid JSON:", process_payload('{"name":"John"}'))
    print("2. Valid JSON with special chars:", process_payload('{"name":"O\'Brien"}'))
    print("3. Missing name field:", process_payload('{"age":30}'))
    print("4. Invalid JSON:", process_payload('{invalid}'))
    print("5. None payload:", process_payload(None))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")
        httpd.shutdown()


if __name__ == "__main__":
    main()
