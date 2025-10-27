import html
from http.server import BaseHTTPRequestHandler, HTTPServer

def http_hello_page(username):
    """
    Constructs an HTML page with a greeting for the given username.
    This function contains the core logic separate from the server implementation.
    """
    # Security: Escape username to prevent Cross-Site Scripting (XSS)
    escaped_username = html.escape(username)
    
    # Construct the response body (the HTML page) into the outputbuf variable.
    outputbuf = f"""
    <html>
        <head><title>Hello</title></head>
        <body>
            <h1>Hello, {escaped_username}!</h1>
        </body>
    </html>
    """
    return outputbuf.encode('utf-8')

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # The function is called when the server receives a request for the URL /hello.
        if self.path == '/hello':
            try:
                # Security: Check content length to prevent Denial of Service attacks.
                content_length = int(self.headers['Content-Length'])
                max_body_size = 1024
                if content_length > max_body_size:
                    self.send_response(413) # Payload Too Large
                    self.end_headers()
                    self.wfile.write(b"Request body too large.")
                    return

                # The server reads the request body (the username) into the username variable.
                request_body = self.rfile.read(content_length)
                username = request_body.decode('utf-8')

                # Get the response from the core logic function
                response_body = http_hello_page(username)

                # Send response status code
                self.send_response(200)
                
                # Send headers
                self.send_header('Content-type', 'text/html; charset=utf-8')
                # Security: Add basic security headers
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Content-Security-Policy', "default-src 'self'")
                self.end_headers()

                # The server writes the response body to the response stream.
                self.wfile.write(response_body)

            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Server error: {e}".encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_GET(self):
        # For /hello, only POST is allowed.
        if self.path == '/hello':
            self.send_response(405) # Method Not Allowed
            self.end_headers()
            self.wfile.write(b"Method Not Allowed. Please use POST.")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")


def main():
    """Main function to run the server and show test cases."""
    port = 8080
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"Server started on port {port}")
    print("Run the following commands in another terminal to test:")
    
    # Test cases documentation
    print("\n--- 5 Test Cases ---")
    print("1. Normal name:")
    print("   curl -X POST -d \"World\" http://localhost:8080/hello")
    print("\n2. Name with spaces (should be URL encoded or quoted):")
    print("   curl -X POST -d \"Bob Smith\" http://localhost:8080/hello")
    print("\n3. Empty name:")
    print("   curl -X POST -d \"\" http://localhost:8080/hello")
    print("\n4. Malicious XSS attempt (should be safely escaped):")
    print("   curl -X POST -d \"<script>alert('xss')</script>\" http://localhost:8080/hello")
    print("\n5. Name with HTML special characters:")
    print("   curl -X POST -d \"O'Malley & Sons <Company>\" http://localhost:8080/hello")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
        httpd.server_close()

if __name__ == '__main__':
    main()