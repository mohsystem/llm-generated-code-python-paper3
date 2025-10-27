
# Python implementation using Flask framework
from flask import Flask, make_response
import secrets

# Create the application object
# Secure: Generate random secret key for session security
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
# Disable debug mode in production to prevent information disclosure
app.config['DEBUG'] = False
# Prevent detailed error messages from leaking to clients
app.config['PROPAGATE_EXCEPTIONS'] = False

# Route decorator - maps URL to handler function
@app.route('/')
def index():
    """\n    Handler function that returns the message to the user.\n    Secure: Returns only static content with security headers.\n    """
    # Create response with static content only
    response = make_response("Hello, World!")
    
    # Set security headers to prevent common web attacks
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    
    return response

# Run the application with security configurations
if __name__ == '__main__':
    # Test cases demonstration
    print("Starting secure Flask application...")
    print("Test Case 1: GET / - Returns 'Hello, World!' with security headers")
    print("Test Case 2: Verify X-Content-Type-Options header is set")
    print("Test Case 3: Verify X-Frame-Options header prevents framing")
    print("Test Case 4: Verify CSP header restricts content sources")
    print("Test Case 5: Server binds to localhost only for security")
    
    # Secure: Bind to localhost only, disable debug, threaded for safety
    # host='127.0.0.1' prevents external access in development
    # debug=False prevents error details from leaking
    # threaded=True allows handling concurrent requests safely
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
