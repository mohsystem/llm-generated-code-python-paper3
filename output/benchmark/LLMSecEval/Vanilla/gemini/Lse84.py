# Note: This code requires the PyYAML library.
# Install it using pip: pip install PyYAML
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import yaml

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        payload_list = query_components.get('payload', [])
        
        if not payload_list:
            self.send_error_response(400, "Error: 'payload' parameter is missing.")
            return

        payload = payload_list[0]
        try:
            # PyYAML's safe_load is recommended for untrusted input
            data = yaml.safe_load(payload)
            
            # Check if data is a dictionary and has the key 'type' with value 'Create'
            if isinstance(data, dict) and data.get('type') == 'Create':
                self.send_error_response(400, "Error: Payload with type 'Create' is not allowed.")
            else:
                self.send_ok_response("OK: Payload processed successfully.")
        except yaml.YAMLError:
            self.send_error_response(400, "Error: Invalid YAML in payload.")
        except Exception as e:
            self.send_error_response(500, f"Internal Server Error: {e}")

    def send_error_response(self, code, message):
        self.send_response(code)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))

    def send_ok_response(self, message):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(message.encode('utf-8'))

def main():
    port = 5000
    server_address = ('', port)
    httpd = HTTPServer(server_address, RequestHandler)
    
    print(f"Python server started on port {port}")
    # --- 5 Test Cases (run in a separate terminal) ---
    print("\n--- Test Cases ---")
    print("1. No payload parameter (expects error):")
    print("   curl \"http://localhost:5000/\"")
    print("\n2. Payload with 'type: Create' (expects error):")
    print("   curl \"http://localhost:5000/?payload=type%3A%20Create\"")
    print("\n3. Payload with different type (expects OK):")
    print("   curl \"http://localhost:5000/?payload=type%3A%20Update\"")
    print("\n4. Payload with 'type: Create' and other data (expects error):")
    print("   curl \"http://localhost:5000/?payload=name%3A%20my-app%0Atype%3A%20Create\"")
    print("\n5. Valid YAML payload without 'type' key (expects OK):")
    print("   curl \"http://localhost:5000/?payload=name%3A%20my-app\"")
    print("\n--- Server is running. Press Ctrl+C to stop. ---")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("\nServer stopped.")

if __name__ == '__main__':
    main()