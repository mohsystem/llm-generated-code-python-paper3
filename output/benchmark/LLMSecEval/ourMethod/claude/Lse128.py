
import re
import html
import sys
from typing import BinaryIO, Optional

MAX_USERNAME_LENGTH = 100
MAX_REQUEST_SIZE = 8192
VALID_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

def sanitize_username(username: Optional[str]) -> Optional[str]:
    """\n    Validate and sanitize username input\n    Only allow alphanumeric characters, underscore, and hyphen\n    """
    if not username:
        return None
    
    # Trim whitespace and enforce length limit
    username = username.strip()
    if len(username) > MAX_USERNAME_LENGTH or len(username) == 0:
        return None
    
    # Validate against allowed pattern
    if not VALID_USERNAME_PATTERN.match(username):
        return None
    
    return username

def html_encode(text: str) -> str:
    """\n    HTML encode text to prevent XSS attacks\n    """
    if not text:
        return ""
    return html.escape(text, quote=True)

def http_hello_page(request: BinaryIO, response: BinaryIO) -> None:
    """\n    Process HTTP request and generate hello page response\n    \n    Args:\n        request: Input stream containing HTTP request\n        response: Output stream for HTTP response\n    """
    try:
        username = None
        bytes_read = 0
        
        # Read request line by line with size limit
        while bytes_read < MAX_REQUEST_SIZE:
            line_bytes = request.readline()
            if not line_bytes:
                break
            
            bytes_read += len(line_bytes)
            line = line_bytes.decode('utf-8', errors='ignore').strip()
            
            # Empty line indicates end of headers
            if not line:
                break
            
            # Parse GET request line for username parameter
            if line.startswith('GET '):
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    path = parts[1]
                    query_start = path.find('?')
                    if query_start != -1:
                        query = path[query_start + 1:]
                        params = query.split('&')
                        for param in params:
                            kv = param.split('=', 1)
                            if len(kv) == 2 and kv[0] == 'username':
                                # URL decode username
                                import urllib.parse
                                username = urllib.parse.unquote_plus(kv[1])
                                break
        
        # Validate and sanitize username
        sanitized_username = sanitize_username(username)
        
        # Construct response
        if sanitized_username:
            # HTML encode for safe output
            encoded_username = html_encode(sanitized_username)
            
            # Write HTTP response with security headers
            response.write(b'HTTP/1.1 200 OK\\r\\n')
            response.write(b'Content-Type: text/html; charset=UTF-8\\r\\n')
            response.write(b'X-Content-Type-Options: nosniff\\r\\n')
            response.write(b'X-Frame-Options: DENY\\r\\n')
            response.write(b'Cache-Control: no-store\\r\\n')
            response.write(b'\\r\\n')
            response.write(b'<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>')
            response.write(f'hello {encoded_username}'.encode('utf-8'))
            response.write(b'</body></html>')
        else:
            # Return generic error without exposing details
            response.write(b'HTTP/1.1 400 Bad Request\\r\\n')
            response.write(b'Content-Type: text/plain; charset=UTF-8\\r\\n')
            response.write(b'\\r\\n')
            response.write(b'Invalid username')
        
        response.flush()
        
    except Exception:
        # Log error securely without exposing details
        print("Error processing request", file=sys.stderr)

def main():
    """Test cases"""
    import io
    
    test_cases = [
        (b'GET /?username=john HTTP/1.1\\r\\n\\r\\n', 'Valid username'),
        (b'GET /?username=john<script> HTTP/1.1\\r\\n\\r\\n', 'XSS attempt'),
        (b'GET /?username=' + b'a' * 150 + b' HTTP/1.1\\r\\n\\r\\n', 'Long username'),
        (b'GET /?username=john_doe HTTP/1.1\\r\\n\\r\\n', 'Username with underscore'),
        (b'GET / HTTP/1.1\\r\\n\\r\\n', 'No username'),
    ]
    
    for request_data, description in test_cases:
        print(f'\\n=== Test: {description} ===')
        request_stream = io.BytesIO(request_data)
        response_stream = io.BytesIO()
        
        http_hello_page(request_stream, response_stream)
        
        print(response_stream.getvalue().decode('utf-8', errors='ignore'))

if __name__ == '__main__':
    main()
