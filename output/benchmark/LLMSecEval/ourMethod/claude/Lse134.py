
from flask import Flask, escape as flask_escape
import re
from typing import Optional

app = Flask(__name__)

# Whitelist pattern for username validation
VALID_USERNAME = re.compile(r'^[a-zA-Z0-9_-]{1,50}$')

def escape(text: str) -> str:
    """\n    HTML escape function to prevent XSS attacks.\n    Validates input length and escapes special characters.\n    """
    if text is None:
        return ""
    
    # Validate input length to prevent DoS
    if len(text) > 1000:
        return ""
    
    # Escape HTML special characters
    escaped = text.replace("&", "&amp;")
    escaped = escaped.replace("<", "&lt;")
    escaped = escaped.replace(">", "&gt;")
    escaped = escaped.replace('"', "&quot;")
    escaped = escaped.replace("'", "&#x27;")
    escaped = escaped.replace("/", "&#x2F;")
    
    return escaped

def hello(username: Optional[str]) -> str:
    """\n    Returns greeting with validated and escaped username.\n    Input validation prevents injection attacks.\n    """
    # Input validation - reject null or empty
    if not username:
        return "Hello Guest"
    
    # Validate username against whitelist pattern
    if not VALID_USERNAME.match(username):
        return "Hello Guest"
    
    # Escape the username to prevent XSS
    escaped_username = escape(username)
    return f"Hello {escaped_username}"

# Decorator creates mapping between URL and function
@app.route('/hello/<username>')
def hello_route(username: str) -> str:
    """\n    Route handler for /hello/<username>.\n    Validates and sanitizes username before processing.\n    """
    # Additional validation on URL parameter
    if not username or len(username) > 50:
        return "Hello Guest", 400
    
    # Call hello function with username
    response = hello(username)
    
    # Set secure headers
    from flask import make_response
    resp = make_response(response)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    
    return resp

if __name__ == '__main__':
    # Test cases
    print("Test 1:", hello("john"))
    print("Test 2:", hello("alice_123"))
    print("Test 3:", hello("<script>alert('xss')</script>"))
    print("Test 4:", hello("user-name"))
    print("Test 5:", hello(None))
    
    # Run server on localhost only for security
    app.run(host='127.0.0.1', port=5000, debug=False)
