
from flask import Flask, request
import subprocess
import re
import shlex

app = Flask(__name__)

# Whitelist pattern: only alphanumeric, dots, hyphens allowed
# Prevents command injection by validating input format
VALID_HOST_PATTERN = re.compile(r'^[a-zA-Z0-9.-]+$')
MAX_HOST_LENGTH = 253  # RFC 1035 max domain length
MAX_OUTPUT_SIZE = 65536  # 64KB output limit

@app.route('/ping')
def ping():
    """\n    Decorator @app.route binds this function to the /ping URL endpoint.\n    Extracts 'url' parameter and executes ping command safely.\n    """
    try:
        # Extract URL parameter from query string
        url = request.args.get('url', '')
        
        if not url:
            # Input validation: reject empty input
            return "Error: Missing 'url' parameter", 400
        
        if not is_valid_host(url):
            # Input validation: reject invalid hostnames to prevent command injection
            return "Error: Invalid URL format", 400
        
        # Execute ping command with validated input
        result = execute_ping(url)
        return result, 200
        
    except Exception:
        # Fail closed: return generic error without exposing internal details
        return "Error: Request processing failed", 500

def is_valid_host(host):
    """\n    Validates hostname format to prevent command injection.\n    Rejects shell metacharacters and enforces length limits.\n    """
    # Check length to prevent buffer issues
    if len(host) > MAX_HOST_LENGTH:
        return False
    # Check format: only safe characters allowed
    # Rejects shell metacharacters like ;|&$()` etc.
    return VALID_HOST_PATTERN.match(host) is not None

def execute_ping(host):
    """\n    Executes ping command safely using subprocess with argument list.\n    Prevents shell injection by not using shell=True.\n    """
    try:
        # Use subprocess with argument list - prevents shell injection
        # No shell involved, arguments passed directly to ping binary
        # Limit to 4 packets for safety
        result = subprocess.run(
            ['ping', '-c', '4', host],
            capture_output=True,
            text=True,
            timeout=10,  # Timeout to prevent hanging
            check=False
        )
        
        # Limit output size to prevent memory exhaustion
        output = result.stdout + result.stderr
        if len(output) > MAX_OUTPUT_SIZE:
            return "Error: Output too large"
        
        return f"Ping result for {host}:\\n{output}"
        
    except subprocess.TimeoutExpired:
        return "Error: Ping timeout"
    except Exception:
        # Generic error message - no internal details leaked
        return "Error: Ping execution failed"

if __name__ == '__main__':
    # Test cases demonstrating usage
    print("Server starting on http://localhost:5000")
    print("\\nTest cases:")
    print("1. http://localhost:5000/ping?url=localhost")
    print("2. http://localhost:5000/ping?url=127.0.0.1")
    print("3. http://localhost:5000/ping?url=google.com")
    print("4. http://localhost:5000/ping?url=")
    print("5. http://localhost:5000/ping?url=invalid;command")
    
    # Run server (debug=False for production)
    app.run(host='localhost', port=5000, debug=False)
