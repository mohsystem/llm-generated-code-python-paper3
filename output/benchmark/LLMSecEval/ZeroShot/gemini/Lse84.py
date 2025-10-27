# NOTE: This code requires the PyYAML library.
# Install it using pip: pip install PyYAML
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import yaml

def handle_payload(payload_str):
    """
    Parses the payload and checks its type.
    
    Returns a tuple of (status_code, message).
    """
    if not payload_str:
        return 400, "Error: 'payload' parameter is present but empty."

    try:
        # yaml.safe_load() is crucial for security. It prevents arbitrary code execution.
        data = yaml.safe_load(payload_str)
        if not isinstance(data, dict):
             return 400, "Error: Payload must be a YAML mapping (key-value pairs)."
        
        payload_type = data.get('type')
        if payload_type == 'Create':
            return 400, "Error: 'Create' type is not allowed."
        else:
            return 200, "Payload processed successfully."

    except yaml.YAMLError as e:
        return 400, f"Error: Could not parse YAML payload. {e}"

class Lse84(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)

        if 'payload' not in query_params:
            status_code = 400
            message = "Error: 'payload' parameter is missing."
        else:
            # parse_qs returns a list for each param, get the first element
            payload = query_params['payload'][0]
            status_code, message = handle_payload(payload)

        self.send_response(status_code)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))

def run(server_class=HTTPServer, handler_class=Lse84, port=5000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting server on port {port}...')
    
    print("Running 5 test cases using curl:")
    print("1. No 'payload' parameter: curl -i \"http://localhost:5000/test\"")
    print("2. 'payload' with 'type: Create': curl -i \"http://localhost:5000/?payload=type%3A%20Create\"")
    print("3. Valid 'payload': curl -i \"http://localhost:5000/?payload=type%3A%20Update%0Aname%3A%20test\"")
    print("4. Malformed YAML in 'payload': curl -i \"http://localhost:5000/?payload=type%3A%20%5Binvalid\"")
    print("5. Empty 'payload': curl -i \"http://localhost:5000/?payload=\"")

    httpd.serve_forever()

if __name__ == "__main__":
    run()