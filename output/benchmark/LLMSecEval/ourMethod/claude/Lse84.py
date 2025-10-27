
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import yaml
from yaml import SafeLoader
import sys

# Maximum payload size to prevent DoS attacks
MAX_PAYLOAD_SIZE = 10240  # 10KB
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import yaml
from yaml.loader import SafeLoader

MAX_PAYLOAD_SIZE = 10240  # 10 KB limit


class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handle POST requests securely"""
        try:
            parsed_path = urlparse(self.path)
            params = parse_qs(parsed_path.query)

            # Check if payload parameter exists
            if 'payload' not in params:
                self.send_error_response("Error: Missing payload parameter", 400)
                return

            # Get payload (parse_qs returns lists)
            payload = params['payload'][0] if params['payload'] else ""

            # Validate payload size to prevent DoS
            if len(payload) > MAX_PAYLOAD_SIZE:
                self.send_error_response("Error: Payload too large", 400)
                return

            # Process payload
            response = process_payload(payload)
            self.send_success_response(response)

        except Exception:
            # Generic error message - don’t leak internal details
            self.send_error_response("Error: Invalid request", 400)

    def do_GET(self):
        """Reject GET requests"""
        self.send_error_response("Error: Method not allowed", 405)

    def send_success_response(self, message):
        """Send successful response"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))

    def send_error_response(self, message, code):
        """Send error response"""
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))

    def log_message(self, format, *args):
        """Override to prevent logging sensitive data"""
        pass  # Intentionally suppress sensitive data logging


def process_payload(payload):
    """
    Process YAML payload securely.
    Uses SafeLoader to prevent arbitrary code execution.
    """
    try:
        # Use SafeLoader to prevent code execution vulnerabilities
        data = yaml.load(payload, Loader=SafeLoader)

        # Validate parsed data is a dictionary
        if not isinstance(data, dict):
            return "Error: Invalid payload format"

        # Check if type field exists and equals "Create"
        if 'type' in data and data['type'] == 'Create':
            return "Error: Create type not allowed"

        return "Success: Payload processed"

    except yaml.YAMLError:
        # Don’t leak internal details in error messages
        return "Error: Invalid YAML format"

    except Exception:
        return "Error: Invalid YAML format"

def run_server():
    """Start the HTTP server on port 5000"""
    server_address = ('', 5000)
    httpd = HTTPServer(server_address, RequestHandler)
    print("Server started on port 5000")
    httpd.serve_forever()

def run_test_cases():
    """Run test cases for the payload processor"""
    print("\\n=== Running Test Cases ===")
    
    # Test 1: Valid payload with type=Create
    print("\\nTest 1: Valid YAML with type=Create")
    print(process_payload("type: Create\\ndata: test"))
    
    # Test 2: Valid payload with different type
    print("\\nTest 2: Valid YAML with type=Update")
    print(process_payload("type: Update\\ndata: test"))
    
    # Test 3: Valid payload without type field
    print("\\nTest 3: Valid YAML without type field")
    print(process_payload("data: test\\nvalue: 123"))
    
    # Test 4: Invalid YAML syntax
    print("\\nTest 4: Invalid YAML syntax")
    print(process_payload("invalid: [yaml: syntax"))
    
    # Test 5: Empty payload
    print("\\nTest 5: Empty payload")
    print(process_payload(""))

if __name__ == '__main__':
    # Run test cases first
    run_test_cases()
    
    # Start server
    try:
        run_server()
    except KeyboardInterrupt:
        print("\\nServer stopped")
        sys.exit(0)
