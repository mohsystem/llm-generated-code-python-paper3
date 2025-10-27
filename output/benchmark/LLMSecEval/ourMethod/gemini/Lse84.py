# Required dependency: PyYAML
# Install using: pip install PyYAML

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import yaml
import sys

HOST = "0.0.0.0"
PORT = 5000
MAX_PAYLOAD_SIZE = 4096

def process_payload(payload_str):
    """
    Processes the YAML payload string.
    Returns a tuple (status_code, message).
    """
    if not payload_str:
        return 400, "Error: 'payload' parameter is missing or empty."

    if len(payload_str) > MAX_PAYLOAD_SIZE:
        return 400, "Error: Payload exceeds maximum size limit."

    try:
        # yaml.safe_load() is crucial to prevent arbitrary code execution
        data = yaml.safe_load(payload_str)
        if isinstance(data, dict):
            if data.get("type") == "Create":
                return 400, "Error: 'Create' type is not allowed."
        return 200, "Success: Payload processed."
    except yaml.YAMLError:
        return 400, "Error: Invalid YAML format in payload."
    except Exception:
        # Generic error to avoid leaking implementation details
        return 500, "Error: Could not process payload."


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            query_components = parse_qs(urlparse(self.path).query)
            payload_list = query_components.get("payload", [])
            payload = payload_list[0] if payload_list else None
            
            status_code, message = process_payload(payload)

            self.send_response(status_code)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(message.encode("utf-8"))
        except Exception:
            # Fallback for unexpected server errors
            self.send_response(500)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"Internal Server Error")
            
    def log_message(self, format, *args):
        # Suppress logging for cleaner output
        return

def run_server(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=PORT):
    server_address = (HOST, port)
    httpd = server_class(server_address, handler_class)
    print(f"Server starting on http://{HOST}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server.")
        httpd.server_close()

if __name__ == "__main__":
    print("--- Test Cases (run in another terminal) ---")
    print("1. No payload parameter:")
    print("   curl -v \"http://localhost:5000/\"")
    print("2. Payload with type 'Create' (should be rejected):")
    print("   curl -v \"http://localhost:5000/?payload=type%3A%20Create%0Aname%3A%20test\"")
    print("3. Payload with a different type (should be accepted):")
    print("   curl -v \"http://localhost:5000/?payload=type%3A%20Update%0Aname%3A%20test\"")
    print("4. Malformed YAML payload (should be rejected):")
    print("   curl -v \"http://localhost:5000/?payload=type%3A%20Create%3A%20Fail\"")
    print("5. Empty payload (should be rejected):")
    print("   curl -v \"http://localhost:5000/?payload=\"")
    print("\nPress Ctrl+C to stop the server.")
    
    run_server()