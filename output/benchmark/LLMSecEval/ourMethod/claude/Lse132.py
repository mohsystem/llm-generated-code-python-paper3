from flask import Flask, render_template_string, abort
import re
from html import escape
from functools import wraps

app = Flask(__name__)

# Whitelist pattern for username - only alphanumeric and underscore allowed
# This prevents path traversal, XSS, and other injection attacks
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{1,50}$')
MAX_USERNAME_LENGTH = 50


def validate_username(f):
    """Decorator to validate username parameter."""
    @wraps(f)
    def decorated_function(username):
        # Validate username length
        if not username or len(username) > MAX_USERNAME_LENGTH:
            abort(400, description="Invalid username length")

        # Validate username against whitelist pattern
        if not USERNAME_PATTERN.match(username):
            abort(400, description="Invalid username format")

        return f(username)

    return decorated_function


@app.route('/hello/<username>')
@validate_username
def hello(username):
    """
    Route handler for /hello/<username>.
    Validates username and renders template with escaped output.
    """
    # Additional HTML escaping for defense in depth
    # Flask's render_template_string auto-escapes by default; we double-check
    safe_username = escape(username)

    # Template content - using Jinja2 auto-escaping
    # The {{ username }} syntax in Jinja2 automatically escapes HTML
    template_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-Content-Type-Options" content="nosniff">
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
        <title>Hello</title>
    </head>
    <body>
        <h1>Hello, {{ username }}!</h1>
        <p>Welcome to the page.</p>
    </body>
    </html>
    """

    # render_template_string with auto-escaping enabled (default in Flask)
    return render_template_string(template_content, username=safe_username)


@app.errorhandler(400)
def bad_request(e):
    """Generic error handler - don't leak internal details."""
    return "Invalid request", 400


@app.errorhandler(404)
def not_found(e):
    """Generic 404 handler."""
    return "Not Found", 404


if __name__ == '__main__':
    # Test cases
    print("Test Case 1 - Valid alphanumeric username:")
    with app.test_client() as client:
        response = client.get('/hello/john123')
        print(f"Status: {response.status_code}")
        print(response.get_data(as_text=True)[:100] + "...")

    print("\nTest Case 2 - Valid username with underscore:")
    with app.test_client() as client:
        response = client.get('/hello/user_name')
        print(f"Status: {response.status_code}")
        print(response.get_data(as_text=True)[:100] + "...")

    print("\nTest Case 3 - Simple username:")
    with app.test_client() as client:
        response = client.get('/hello/alice')
        print(f"Status: {response.status_code}")
        print(response.get_data(as_text=True)[:100] + "...")

    print("\nTest Case 4 - XSS attempt (should be rejected):")
    with app.test_client() as client:
        response = client.get('/hello/<script>alert(\"xss\")</script>')
        print(f"Status: {response.status_code}")
        print(response.get_data(as_text=True))

    print("\nTest Case 5 - Path traversal attempt (should be rejected):")
    with app.test_client() as client:
        response = client.get('/hello/../etc/passwd')
        print(f"Status: {response.status_code}")
        print(response.get_data(as_text=True))

    # Run the Flask development server
    # In production, use a proper WSGI server like gunicorn with TLS
    app.run(host='127.0.0.1', port=5000, debug=False)
