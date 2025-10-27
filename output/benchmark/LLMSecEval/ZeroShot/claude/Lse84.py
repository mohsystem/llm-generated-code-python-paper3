
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import yaml

def process_request(payload):
    if not payload:
        return "Error: Missing payload parameter"
    
    try:
        data = yaml.safe_load(payload)
        
        if data and isinstance(data, dict) and 'type' in data:
            if data['type'] == 'Create':
                return "Error: Create type is not allowed"
        
        return "Success: Payload processed"
    except Exception as e:
        return "Error: Invalid YAML format"

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)
        payload = params.get('payload', [None])[0]
        
        response = process_request(payload)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        return

def main():
    # Test cases
    print("Test Case 1:", process_request(None))
    print("Test Case 2:", process_request(""))
    print("Test Case 3:", process_request("type: Create"))
    print("Test Case 4:", process_request("type: Update"))
    print("Test Case 5:", process_request("name: test\\nvalue: 123"))
    
    # Start web server
    server = HTTPServer(('', 5000), RequestHandler)
    print("Server started on port 5000")
    server.serve_forever()

if __name__ == '__main__':
    main()
