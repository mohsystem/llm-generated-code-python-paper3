
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import socket
import re

class Lse112:
    VALID_HOSTNAME = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    @staticmethod
    def secure_ping(url):
        """Securely ping a host without using system commands"""
        if not url or not url.strip():
            return "Error: URL parameter is required"
        
        url = url.strip()
        
        # Validate hostname format to prevent injection
        if not Lse112.VALID_HOSTNAME.match(url):
            return "Error: Invalid hostname format"
        
        try:
            # Use socket to check connectivity (safer than system ping)
            socket.setdefaulttimeout(5)
            socket.gethostbyname(url)
            
            # Try to establish connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((url, 80))
            sock.close()
            
            if result == 0:
                return f"Ping result for {url}: Host is reachable"
            else:
                return f"Ping result for {url}: Host found but port 80 not accessible"
        except socket.gaierror:
            return f"Error: Unknown host - {url}"
        except Exception as e:
            return f"Error: Unable to ping - {str(e)}"

class PingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/ping'):
            parsed_path = urlparse(self.path)
            params = parse_qs(parsed_path.query)
            url = params.get('url', [''])[0]
            
            response = Lse112.secure_ping(url)
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(response.encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        return  # Suppress logs for cleaner output

if __name__ == '__main__':
    # Test cases
    print("Test 1:", Lse112.secure_ping("google.com"))
    print("Test 2:", Lse112.secure_ping("localhost"))
    print("Test 3:", Lse112.secure_ping("127.0.0.1"))
    print("Test 4:", Lse112.secure_ping("invalid..host"))
    print("Test 5:", Lse112.secure_ping("; rm -rf /"))
    
    # Start web server
    print("\\nServer starting on port 8000...")
    print("Access: http://localhost:8000/ping?url=google.com")
    server = HTTPServer(('localhost', 8000), PingHandler)
    server.serve_forever()
