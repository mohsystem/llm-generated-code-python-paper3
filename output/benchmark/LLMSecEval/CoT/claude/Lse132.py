
# Python - Using Flask Framework
from flask import Flask, render_template_string, escape
import re

app = Flask(__name__)

# Template string (in production, use separate template file)
TEMPLATE = '''\n<!DOCTYPE html>\n<html>\n<head><title>Hello</title></head>\n<body>\n    <h1>Hello, {{ username }}!</h1>\n    {% if error %}\n        <p style="color: red;">{{ error }}</p>\n    {% endif %}\n</body>\n</html>\n'''

@app.route('/hello/<username>')
def hello(username):
    """\n    Secure hello function with input validation and sanitization\n    """
    # Input validation - only allow alphanumeric characters, underscore, and hyphen
    if not username or not re.match(r'^[a-zA-Z0-9_-]{1,50}$', username):
        return render_template_string(
            TEMPLATE, 
            username="Invalid User",
            error="Username must be alphanumeric (1-50 chars)"
        ), 400
    
    # Flask auto-escapes by default, but explicit escaping for extra security
    sanitized_username = escape(username)
    
    return render_template_string(TEMPLATE, username=sanitized_username)

if __name__ == '__main__':
    # Test cases
    print("Test cases for /hello/<username>:")
    test_cases = [
        "john",
        "jane_doe",
        "user-123",
        "<script>alert('xss')</script>",
        "verylongusernamethatshouldbevalidatedproperly"
    ]
    
    with app.test_client() as client:
        for i, test_username in enumerate(test_cases, 1):
            response = client.get(f'/hello/{test_username}')
            print(f"{i}. /hello/{test_username} - Status: {response.status_code}")
    
    # Uncomment to run the server
    # app.run(debug=False, host='127.0.0.1', port=5000)
