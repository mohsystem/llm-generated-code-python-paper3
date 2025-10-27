
import http.server
import socketserver
from html import escape
from io import BytesIO
import sys

# Maximum allowed request body size to prevent resource exhaustion
MAX_REQUEST_BODY_SIZE = 8192  # 8KB
# Maximum username length
MAX_USERNAME_LENGTH = 256


def http_hello_page(handler):
    """\n    Handle HTTP request for /hello endpoint.\n    Reads username from request body and returns HTML greeting.\n    """
    try:
        # Only accept POST requests
        if handler.command != 'POST':
            send_error(handler, 405, "Method Not Allowed")
            return
        
        # Get Content-Length header with validation
        content_length_str = handler.headers.get('Content-Length', '0')
        try:
            content_length = int(content_length_str)
        except ValueError:
            send_error(handler, 400, "Invalid Content-Length")
            return
        
        # Enforce maximum request body size to prevent DoS
        if content_length > MAX_REQUEST_BODY_SIZE:
            send_error(handler, 413, "Request Entity Too Large")
            return
        
        # Read request body with size enforcement
        username = handler.rfile.read(content_length).decode('utf-8', errors='strict')
        
        # Validate username
        if not username or not username.strip():
            send_error(handler, 400, "Invalid Request")
            return
        
        # Trim and enforce maximum username length
        username = username.strip()
        if len(username) > MAX_USERNAME_LENGTH:
            send_error(handler, 400, "Invalid Request")
            return
        
        # Sanitize username to prevent XSS (HTML entity encoding)
        username_safe = escape(username, quote=True)
        
        # Construct response HTML
        outputbuf = BytesIO()
        html_content = f"""<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n<title>Hello Page</title>\n</head>\n<body>\n<h1>Hello, {username_safe}!</h1>\n</body>\n</html>"""
        
        outputbuf.write(html_content.encode('utf-8'))
        response_bytes = outputbuf.getvalue()
        
        # Send response headers
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/html; charset=UTF-8')
        handler.send_header('Content-Length', str(len(response_bytes)))
        # Security headers
        handler.send_header('X-Content-Type-Options', 'nosniff')
        handler.send_header('X-Frame-Options', 'DENY')
        handler.send_header('Content-Security-Policy', "default-src 'self'")
        handler.end_headers()
        
        # Write response body
        handler.wfile.write(response_bytes)
        handler.wfile.flush()
        
    except UnicodeDecodeError:
        send_error(handler, 400, "Invalid UTF-8 encoding")
    except Exception as e:
        # Log error without exposing internal details
        print("Error processing request", file=sys.stderr)
        send_error(handler, 500, "Internal Server Error")


def send_error(handler, status_code, message):
    """Send error response with proper headers."""
    try:
        response = message.encode('utf-8')
        handler.send_response(status_code)
        handler.send_header('Content-Type', 'text/plain; charset=UTF-8')
        handler.send_header('Content-Length', str(len(response)))
        handler.end_headers()
        handler.wfile.write(response)
        handler.wfile.flush()
    except Exception:
        print("Error sending error response", file=sys.stderr)


class HelloHandler(http.server.BaseHTTPRequestHandler):
    """Custom request handler for /hello endpoint."""
    
    def do_POST(self):
        """Handle POST requests."""
        if self.path == '/hello':
            http_hello_page(self)
        else:
            send_error(self, 404, "Not Found")
    
    def log_message(self, format, *args):
        """Override to control logging."""
        sys.stderr.write("%s - - [%s] %s\\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format % args))


def main():
    """Start server and run test cases."""
    PORT = 8080
    
    # Test cases
    test_cases = [
        "Alice",
        "Bob123",
        "<script>alert('xss')</script>",
        "A" * 300,  # Long username
        ""  # Empty username
    ]
    
    print(f"Starting server on port {PORT}")
    print("\\nRunning test cases:\\n")
    
    import urllib.request
    import urllib.error
    
    # Start server in background for testing
    import threading
    with socketserver.TCPServer(("", PORT), HelloHandler) as httpd:
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()
        
        import time
        time.sleep(1)  # Wait for server to start
        
        for username in test_cases:
            try:
                data = username.encode('utf-8')
                req = urllib.request.Request(
                    f'http://localhost:{PORT}/hello',
                    data=data,
                    method='POST'
                )
                req.add_header('Content-Type', 'text/plain; charset=UTF-8')
                
                with urllib.request.urlopen(req, timeout=5) as response:
                    print(f"Test username: {username[:50]}")
                    print(f"Response code: {response.status}")
                    print(response.read().decode('utf-8'))
                    print()
            except urllib.error.HTTPError as e:
                print(f"Test username: {username[:50]}")
                print(f"HTTP Error {e.code}: {e.reason}\\n")
            except Exception as e:
                print(f"Test failed: {e}\\n")
        
        httpd.shutdown()


if __name__ == '__main__':
    main()
