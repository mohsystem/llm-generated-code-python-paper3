
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, unquote
import sys

def is_valid_example_url(url_string):
    """\n    Validates if the URL is from example.com domain.\n    Returns True only for https://example.com or https://*.example.com URLs.\n    """
    if not url_string or not url_string.strip():
        return False
    
    try:
        # Parse URL to extract components
        parsed = urlparse(url_string)
        
        # Ensure absolute URL with scheme
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # Only allow https for security
        if parsed.scheme.lower() != 'https':
            return False
        
        # Get hostname and normalize to lowercase
        host = parsed.netloc.lower()
        
        # Remove port if present
        if ':' in host:
            host = host.split(':')[0]
        
        # Check if host is exactly example.com or subdomain of example.com
        # Prevent bypass attempts like "example.com.evil.com"
        if host == 'example.com' or host.endswith('.example.com'):
            return True
        
        return False
    except Exception:
        # Any parsing error means invalid URL
        return False

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Check if path starts with /redirect/
        if self.path.startswith('/redirect/'):
            # Extract URL parameter (everything after /redirect/)
            url_param = self.path[len('/redirect/'):]
            
            # URL decode the parameter
            url_param = unquote(url_param)
            
            # Validate the URL
            if is_valid_example_url(url_param):
                # Valid example.com URL - send redirect
                self.send_response(302)
                self.send_header('Location', url_param)
                self.end_headers()
            else:
                # Invalid URL - return error
                self.send_response(400)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                error_msg = 'Error: Invalid URL. Only example.com URLs are allowed.'
                self.wfile.write(error_msg.encode('utf-8'))
        else:
            # Invalid path
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'Not Found')
    
    def log_message(self, format, *args):
        # Suppress default logging to avoid leaking sensitive data
        pass

def main():
    # Test cases
    print("Test Case 1 - Valid example.com URL:")
    print(is_valid_example_url("https://example.com/page"))
    
    print("\\nTest Case 2 - Valid subdomain:")
    print(is_valid_example_url("https://sub.example.com/path"))
    
    print("\\nTest Case 3 - Invalid domain:")
    print(is_valid_example_url("https://evil.com"))
    
    print("\\nTest Case 4 - Bypass attempt:")
    print(is_valid_example_url("https://example.com.evil.com"))
    
    print("\\nTest Case 5 - HTTP not allowed:")
    print(is_valid_example_url("http://example.com"))
    
    # Start server on port 8000
    server = HTTPServer(('localhost', 8000), RedirectHandler)
    print("\\nServer started on port 8000")
    server.serve_forever()

if __name__ == '__main__':
    main()
