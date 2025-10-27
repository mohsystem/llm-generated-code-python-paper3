
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
import re
import sys

# Strict regex pattern that only matches URLs containing example.com
# Anchored pattern to prevent bypass attempts
ALLOWED_PATTERN = re.compile(r'^https://([a-zA-Z0-9-]+\\.)*example\\.com(/.*)?$')

# Maximum URL length to prevent DoS
MAX_URL_LENGTH = 2048


def is_valid_redirect(url):
    """\n    Validate if the URL matches the allowed pattern.\n    \n    Args:\n        url: The URL string to validate\n        \n    Returns:\n        bool: True if URL is valid, False otherwise\n    """
    if not url or not isinstance(url, str):
        return False
    
    # Length check to prevent DoS
    if len(url) > MAX_URL_LENGTH:
        return False
    
    # Match against whitelist pattern
    return ALLOWED_PATTERN.match(url) is not None


def validate_and_sanitize_url(target):
    """\n    Validate and sanitize the target URL.\n    \n    Args:\n        target: The target URL to validate\n        \n    Returns:\n        str: Validated URL or safe default\n    """
    safe_default = "/"
    
    # Null or empty check
    if not target or not isinstance(target, str):
        return safe_default
    
    # Strip whitespace
    normalized = target.strip()
    
    # Length validation
    if len(normalized) > MAX_URL_LENGTH:
        return safe_default
    
    # Validate against whitelist pattern
    if is_valid_redirect(normalized):
        return normalized
    
    # Return safe default if validation fails
    return safe_default


class RedirectHandler(BaseHTTPRequestHandler):
    """HTTP request handler with URL validation for redirects."""
    
    def do_GET(self):
        """Handle GET requests with secure redirect validation."""
        try:
            # Parse URL and query parameters
            parsed_url = urlparse(self.path)
            
            # Only handle /redirect path
            if parsed_url.path != '/redirect':
                self.send_error(404, "Not Found")
                return
            
            # Extract target parameter securely
            query_params = parse_qs(parsed_url.query)
            target = None
            
            if 'target' in query_params and query_params['target']:
                # Get first value and decode safely
                target = query_params['target'][0]
            
            # Validate and sanitize the target URL
            redirect_url = validate_and_sanitize_url(target)
            
            # Send redirect response with security headers
            self.send_response(302)
            self.send_header('Location', redirect_url)
            # Security headers to prevent additional attacks
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Content-Security-Policy', "default-src 'none'")
            self.end_headers()
            
        except Exception as e:
            # Log error without exposing internal details
            print(f"Error processing request: {type(e).__name__}", file=sys.stderr)
            self.send_error(500, "Internal Server Error")
    
    def log_message(self, format, *args):
        """Override to prevent logging sensitive information."""
        # Minimal logging without exposing parameters
        sys.stderr.write(f"{self.address_string()} - [{self.log_date_time_string()}] "
                        f"{format % args}\\n")


def main():
    """Main function with test cases."""
    # Test cases
    print("Test Cases:")
    print(f"1. Valid: {is_valid_redirect('https://example.com')}")
    print(f"2. Valid: {is_valid_redirect('https://www.example.com/path')}")
    print(f"3. Valid: {is_valid_redirect('https://subdomain.example.com/page')}")
    print(f"4. Invalid: {is_valid_redirect('https://evil.com')}")
    print(f"5. Invalid: {is_valid_redirect('https://evil.com@example.com')}")
    
    # Start web server
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, RedirectHandler)
    print("Server started on port 8000")
    httpd.serve_forever()


if __name__ == '__main__':
    main()
