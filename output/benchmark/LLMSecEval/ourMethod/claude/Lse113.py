
from flask import Flask, request
import socket
import re

app = Flask(__name__)

# Security: Using socket-based connectivity check instead of system ping
# This prevents command injection vulnerabilities (CWE-78)
def ping(url):
    """\n    Safely checks if a host is reachable without using system commands.\n    \n    Args:\n        url: The hostname or IP address to check\n        \n    Returns:\n        str: Status message indicating if the host is alive or not\n    """
    # Input validation: check for None or empty string
    if not url or not isinstance(url, str):
        return "Error: Invalid URL provided"
    
    # Sanitize input: remove whitespace
    url = url.strip()
    
    # Validate URL format - only allow safe characters
    # Reject any characters that could be used for command injection
    if not re.match(r'^[a-zA-Z0-9.\\-:]+$', url):
        return "Error: Invalid URL format"
    
    # Limit URL length to prevent resource exhaustion
    if len(url) > 253:
        return "Error: URL too long"
    
    try:
        # Security: Using socket connection instead of subprocess
        # Attempt to resolve the hostname first
        socket.gethostbyname(url)
        
        # Try to establish a connection (ICMP alternative)
        # Using port 80 as a common reachable port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # 5 second timeout to prevent hanging
        
        result = sock.connect_ex((url, 80))
        sock.close()
        
        # Return code 0 means connection successful
        if result == 0:
            return f"{url} is alive"
        else:
            return f"{url} is not alive"
            
    except socket.gaierror:
        # Host resolution failed - generic error message
        return "Error: Unable to resolve host"
    except socket.timeout:
        return "Error: Connection timeout"
    except Exception:
        # Generic error message to avoid leaking internal details
        return "Error: Network error occurred"

# Decorator to bind function to URL route
@app.route('/ping', methods=['GET'])
def ping_endpoint():
    """\n    HTTP endpoint that accepts a URL parameter and checks if it's reachable.\n    Bound to /ping route using Flask decorator.\n    """
    # Extract URL from query parameters
    url = request.args.get('url', '')
    
    if not url:
        return "Error: URL parameter required", 400
    
    # Call ping function with validated input
    result = ping(url)
    return result

if __name__ == '__main__':
    # Test cases
    print("Test Case 1: Valid domain")
    print(ping("google.com"))
    
    print("\\nTest Case 2: Valid IP")
    print(ping("8.8.8.8"))
    
    print("\\nTest Case 3: Invalid domain")
    print(ping("thisdoesnotexist999.invalid"))
    
    print("\\nTest Case 4: Empty string")
    print(ping(""))
    
    print("\\nTest Case 5: Malicious input attempt")
    print(ping("google.com && cat /etc/passwd"))
    
    # Start Flask server
    # Security: Only bind to localhost in production, use proper WSGI server
    print("\\nStarting server on http://localhost:5000/ping?url=<target>")
    app.run(host='127.0.0.1', port=5000, debug=False)
