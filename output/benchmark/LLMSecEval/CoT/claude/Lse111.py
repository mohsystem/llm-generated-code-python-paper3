
# Requires Flask: pip install flask
from flask import Flask, request
import subprocess
import re
import shlex

app = Flask(__name__)

DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$'
)

IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

@app.route('/ping')
def ping():
    # Get URL parameter
    url = request.args.get('url', '')
    
    # Validate input
    if not url or len(url) > 255:
        return "Invalid input: URL parameter is required and must be less than 255 characters", 400
    
    # Sanitize and validate URL format
    sanitized_url = url.strip()
    if not DOMAIN_PATTERN.match(sanitized_url) and not IP_PATTERN.match(sanitized_url):
        return "Invalid input: Must be a valid domain or IP address", 400
    
    try:
        # Use subprocess with argument list (not shell)
        result = subprocess.run(
            ['ping', '-c', '4', sanitized_url],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        output = result.stdout + result.stderr
        return output
        
    except subprocess.TimeoutExpired:
        return "Error: Ping command timed out", 500
    except Exception as e:
        return f"Error executing ping: {str(e)}", 500

def test_ping_function():
    """Test cases for ping function"""
    with app.test_client() as client:
        print("Test 1 - Valid domain:")
        response = client.get('/ping?url=google.com')
        print(response.data.decode())
        
        print("\\nTest 2 - Valid IP:")
        response = client.get('/ping?url=8.8.8.8')
        print(response.data.decode())
        
        print("\\nTest 3 - Invalid input (command injection attempt):")
        response = client.get('/ping?url=google.com;ls -la')
        print(response.data.decode())
        
        print("\\nTest 4 - Empty input:")
        response = client.get('/ping?url=')
        print(response.data.decode())
        
        print("\\nTest 5 - Invalid format:")
        response = client.get('/ping?url=not_a_valid_domain!')
        print(response.data.decode())

if __name__ == '__main__':
    # Run tests
    test_ping_function()
    
    # Uncomment to run server
    # app.run(debug=False, host='127.0.0.1', port=5000)
