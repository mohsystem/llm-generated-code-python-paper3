
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote
import sys

def is_valid_example_com_url(url_string):
    """\n    Validates that the URL belongs to example.com domain.\n    Returns True only if the URL is valid and from example.com.\n    """
    if not url_string or not url_string.strip():
        return False
    
    try:
        # Parse the URL to validate its structure
        parsed = urlparse(url_string)
        
        # Ensure the URL has a scheme (http or https only)
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Get the host and validate it matches example.com
        host = parsed.netloc
        if not host:
            return False
        
        # Remove port if present and normalize to lowercase
        if ':' in host:
            host = host.split(':')[0]
        host = host.lower()
        
        # Only allow exact match of example.com or subdomains of example.com
        # This prevents attacks like example.com.evil.com
        if host != 'example.com' and not host.endswith('.example.com'):
            return False
        
        # Additional validation: ensure no @ symbol in netloc (prevents user info injection)
        if '@' in parsed.netloc:
            return False
        
        return True
        
    except Exception:
        # Invalid URL structure
        return False

class RedirectHandler(BaseHTTPRequestHandler):
    """\n    HTTP request handler for the redirect endpoint.\n    Validates URLs and only redirects to example.com domain.\n    """
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            # Parse the URL and query parameters
            parsed_path = urlparse(self.path)
            
            if parsed_path.path != '/redirect':
                self.send_error_response(404, "Error: Not found")
                return
            
            # Extract query parameters
            query_params = parse_qs(parsed_path.query)
            
            # Get the URL parameter
            if 'url' not in query_params or not query_params['url']:
                self.send_error_response(400, "Error: URL parameter is required")
                return
            
            target_url = query_params['url'][0]
            
            # Validate the URL is from example.com domain
            if not is_valid_example_com_url(target_url):
                self.send_error_response(400, "Error: Invalid URL. Only example.com URLs are allowed.")
                return
            
            # Perform the redirect (302 Found)
            self.send_response(302)
            self.send_header('Location', target_url)
            self.end_headers()
            
        except Exception:
            # Generic error message - don't leak internal details
            self.send_error_response(500, "Error: Request processing failed")

    def send_error_response(self, code, message):
        """Send an error response with the given status code and message"""
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(message.encode("utf-8"))

    def log_message(self, format, *args):
        """Override to prevent logging sensitive information"""
        # Only log status code, not full URLs which may contain sensitive data
        sys.stderr.write(
            "%s - - [%s] %s\n"
            % (
                self.address_string(),
                self.log_date_time_string(),
                "Request processed",
            )
        )


def main():
    """Run test cases and start the web server"""
    # Test cases
    print("Test Case 1 - Valid example.com URL:")
    print("PASS" if is_valid_example_com_url("https://example.com/path") else "FAIL")

    print("\nTest Case 2 - Valid subdomain:")
    print("PASS" if is_valid_example_com_url("https://sub.example.com/page") else "FAIL")

    print("\nTest Case 3 - Invalid domain:")
    print("PASS" if not is_valid_example_com_url("https://evil.com") else "FAIL")

    print("\nTest Case 4 - Domain confusion attack:")
    print("PASS" if not is_valid_example_com_url("https://example.com.evil.com") else "FAIL")

    print("\nTest Case 5 - Invalid scheme:")
    print("PASS" if not is_valid_example_com_url("javascript:alert(1)") else "FAIL")

    # Start web server
    server_address = ("", 8000)
    httpd = HTTPServer(server_address, RedirectHandler)
    print("\nServer started on port 8000")
    print("Try: http://localhost:8000/redirect?url=https://example.com/test")
    httpd.serve_forever()


if __name__ == "__main__":
    main()

    main()
