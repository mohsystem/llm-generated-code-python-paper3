import html
import re

# In a real web framework like Flask, you would use files and a template engine.
# For this single-file example, we define the template as a string.
HELLO_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Hello Page</title>
</head>
<body>
    <h1>Hello, {username}!</h1>
</body>
</html>
"""

# The following code simulates a web framework's behavior.
# In a real Flask application, the code would look like this:
#
# from flask import Flask, escape
#
# app = Flask(__name__)
#
# @app.route('/hello/<username>')
# def hello(username):
#     # Flask's Jinja2 template engine auto-escapes, so `escape()` is often not needed in the template.
#     # We use f-string here for simplicity, so manual escaping is crucial.
#     safe_username = escape(username)
#     return f"<h1>Hello, {safe_username}!</h1>"
#

def render_hello_page(username):
    """
    Renders the hello page with the given username.
    It escapes the username to prevent XSS attacks.
    """
    # The html.escape() function is crucial for security.
    # It converts characters like '<', '>', and '&' into their HTML-safe equivalents.
    safe_username = html.escape(username)
    return HELLO_TEMPLATE.format(username=safe_username)

def route_request(path):
    """
    Simulates a URL router. It checks if the path matches the '/hello/<username>'
    pattern and calls the appropriate function if it does. This mimics the
    behavior of a decorator like @app.route().
    """
    # Use a regular expression to match the URL and capture the username.
    match = re.match(r'^/hello/([^/]+)$', path)
    if match:
        username = match.group(1)
        return render_hello_page(username)
    else:
        return "404 Not Found"

def main():
    """Main function with 5 test cases."""
    print("--- Running 5 Test Cases ---")
    
    test_cases = [
        # Test Case 1: Simple username
        "/hello/World",
        # Test Case 2: Username with spaces (URL encoded)
        "/hello/Alice%20Smith",
        # Test Case 3: Numeric username
        "/hello/12345",
        # Test Case 4: Path that doesn't match
        "/goodbye/World",
        # Test Case 5: Malicious XSS attempt (should be escaped)
        "/hello/<script>alert('XSS')</script>"
    ]

    for i, path in enumerate(test_cases):
        print(f"Test Case {i+1} (Input Path: {path}):")
        response = route_request(path)
        print(response)
        print("-" * 20)

if __name__ == "__main__":
    main()