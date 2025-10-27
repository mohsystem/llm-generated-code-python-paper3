import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver

def process_payload(payload_str: str) -> str | None:
    """
    Processes a JSON string payload to extract the 'name' field.
    
    Args:
        payload_str: The JSON string payload.
    
    Returns:
        The value of the 'name' field if it exists and is a string, otherwise None.
    """
    if not payload_str:
        return None
    try:
        # Safely parse the JSON payload
        data = json.loads(payload_str)
        # Check if the result is a dictionary and contains the 'name' key
        if isinstance(data, dict):
            name = data.get("name")
            if isinstance(name, str):
                return name
        return None
    except json.JSONDecodeError:
        # Handle cases where the payload is not valid JSON
        return None
    except Exception:
        # Catch any other unexpected errors during processing
        return None

class NameRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        """Handles POST requests."""
        if self.path == '/api/name':
            try:
                content_length_str = self.headers.get('Content-Length')
                if not content_length_str:
                    self.send_response(411) # Length Required
                    self.end_headers()
                    self.wfile.write(b"Content-Length header is required.")
                    return

                content_length = int(content_length_str)
                
                # Set a reasonable limit on payload size to prevent DoS
                MAX_PAYLOAD_SIZE = 1024
                if content_length > MAX_PAYLOAD_SIZE:
                    self.send_response(413) # Payload Too Large
                    self.end_headers()
                    self.wfile.write(f"Payload too large. Max size is {MAX_PAYLOAD_SIZE} bytes.".encode('utf-8'))
                    return
                
                # Read the payload
                post_data = self.rfile.read(content_length)
                
                # Decode and process
                payload_str = post_data.decode('utf-8')
                name = process_payload(payload_str)

                if name is not None:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(name.encode('utf-8'))
                else:
                    self.send_response(400)
                    self.send_header('Content-type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(b"Field 'name' not found or payload is malformed.")

            except (ValueError, UnicodeDecodeError):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Bad Request: Could not process payload.")
            except Exception as e:
                # Generic error for the client
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error.")
                # Log the specific error for the server admin
                print(f"Server error: {e}")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found.")

def run_tests():
    """Runs test cases for the process_payload function."""
    print("--- Running Test Cases ---")
    test_cases = [
        ('{"name":"Alice"}', "Alice"),
        ('{"age":30, "name":"Bob"}', "Bob"),
        ('   { "name" : "Charlie" }   ', "Charlie"),
        ('{"city":"New York"}', None),
        ('invalid json', None),
        ('{"name": 123}', None) # Name must be a string
    ]

    for i, (payload, expected) in enumerate(test_cases):
        result = process_payload(payload)
        is_correct = (result == expected)
        print(f"Test Case {i+1}: Payload='{payload}'")
        print(f"  -> Expected: {expected}, Got: {result}. Correct: {is_correct}")
    print("--- Test Cases Finished ---\n")

def main():
    """Main function to run tests and start the web server."""
    run_tests()
    
    host = 'localhost'
    port = 8080
    
    with socketserver.TCPServer((host, port), NameRequestHandler) as server:
        print(f"Server started on http://{host}:{port}")
        print("Send a POST request to /api/name")
        print("Example: curl -X POST -H \"Content-Type: application/json\" -d '{\"name\":\"YourName\"}' http://localhost:8080/api/name")
        server.serve_forever()

if __name__ == "__main__":
    main()