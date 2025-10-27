
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import re
from typing import Optional

# Maximum payload size to prevent DoS attacks
MAX_PAYLOAD_SIZE = 10 * 1024  # 10KB


def process_payload(payload: str) -> str:
    """\n    Validates and extracts the 'name' field from JSON payload.\n    \n    Args:\n        payload: JSON string containing user data\n        \n    Returns:\n        Name field content or error message\n    """
    # Input validation: check payload is not None or empty
    if not payload or not payload.strip():
        return "Error: Empty payload"
    
    # Input validation: check payload size to prevent DoS
    if len(payload) > MAX_PAYLOAD_SIZE:
        return "Error: Payload too large"
    
    try:
        # Parse JSON with proper error handling
        data = json.loads(payload)
        
        # Validate that parsed data is a dictionary
        if not isinstance(data, dict):
            return "Error: Invalid JSON structure"
        
        # Check if 'name' field exists
        if 'name' in data:
            name = data['name']
            
            # Validate that name is a string type
            if not isinstance(name, str):
                return "Error: Name must be a string"
            
            # Input validation: check name length (max 100 chars)
            if len(name) > 100:
                return "Error: Name too long"
            
            # Input validation: sanitize by allowing only alphanumeric, space, and basic punctuation
            if not re.match(r'^[a-zA-Z0-9 ._-]*$', name):
                return "Error: Invalid characters in name"
            
            # Return sanitized name content
            return name
        else:
            return "Error: Name field not found"
            
    except json.JSONDecodeError as e:
        # Log error internally, return generic message to user
        print(f"JSON parsing error: {e}", file=__import__('sys').stderr)
        return "Error: Invalid JSON format"
    except Exception as e:
        # Catch any unexpected errors
        print(f"Unexpected error: {e}", file=__import__('sys').stderr)
        return "Error: Processing failed"


class PayloadHandler(BaseHTTPRequestHandler):
    """HTTP request handler with security controls"""
    
    def do_POST(self):
        """Handle POST requests only"""
        try:
            # Get content length with validation
            content_length = int(self.headers.get('Content-Length', 0))
            
            # Enforce size limit to prevent DoS
            if content_length > MAX_PAYLOAD_SIZE:
                self.send_error(413, "Payload too large")
                return
            
            # Read request body with size limit
            payload = self.rfile.read(content_length).decode('utf-8')
            
            # Process payload
            result = process_payload(payload)
            
            # Send response with security headers
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            
            # Write response
            self.wfile.write(result.encode('utf-8'))
            
        except Exception as e:
            # Log error internally, return generic message
            print(f"Request handling error: {e}", file=__import__('sys').stderr)
            self.send_error(500, "Internal server error")
    
    def do_GET(self):
        """Reject GET requests"""
        self.send_error(405, "Method not allowed")
    
    def log_message(self, format, *args):
        """Override to prevent logging sensitive data"""
        # Log only status codes, not full requests
        pass


def main():
    """Main function with test cases"""
    print("Test Case 1 - Valid name:")
    print(process_payload('{"name":"John_Doe"}'))
    
    print("\\nTest Case 2 - Missing name field:")
    print(process_payload('{"age":30}'))
    
    print("\\nTest Case 3 - Invalid JSON:")
    print(process_payload('{invalid json}'))
    
    print("\\nTest Case 4 - Name with invalid characters:")
    print(process_payload('{"name":"<script>alert(\'xss\')</script>"}'))
    
    print("\\nTest Case 5 - Empty payload:")
    print(process_payload(''))
    
    # Uncomment to start web server
    # server = HTTPServer(('localhost', 8000), PayloadHandler)
    # print("Server started on port 8000")
    # server.serve_forever()


if __name__ == '__main__':
    main()
