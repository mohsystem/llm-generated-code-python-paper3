import sys
from urllib.parse import urlparse
from flask import Flask, request, redirect, make_response

app = Flask(__name__)

ALLOWED_DOMAIN = "example.com"

@app.route('/redirect')
def redirect_invalid_url_route():
    """
    Flask route handler for the redirect logic.
    Takes 'url' from query parameters.
    """
    url_to_check = request.args.get('url')
    return redirect_invalid_url(url_to_check)

def redirect_invalid_url(url_to_check):
    """
    Checks if the URL has the domain example.com.
    If it is, it returns a redirect response.
    If it is not, it returns an error message.
    """
    if not url_to_check:
        return make_response("URL parameter is missing.", 400)

    try:
        parsed_url = urlparse(url_to_check)
        # Rule #1: Ensure all input is validated.
        # Check for a valid scheme and hostname.
        # This prevents open redirects (CWE-601).
        if parsed_url.scheme in ('http', 'https') and parsed_url.hostname and parsed_url.hostname.lower() == ALLOWED_DOMAIN:
            # Re-encoding the URL to prevent header injection or other attacks
            # by ensuring it's a well-formed location header.
            return redirect(parsed_url.geturl())
        else:
            return make_response("Invalid URL or domain not allowed.", 400)
    except ValueError:
        return make_response("Invalid URL format.", 400)

def main():
    """Main function with test cases."""
    port = 8080
    print(f"Server starting on port {port}", file=sys.stderr)
    print("--- Test Cases ---", file=sys.stderr)
    print("1. Valid Redirect: curl -v \"http://localhost:8080/redirect?url=http%3A%2F%2Fexample.com%2Fsome%2Fpath\"", file=sys.stderr)
    print("2. Valid Redirect (HTTPS): curl -v \"http://localhost:8080/redirect?url=https%3A%2F%2Fexample.com\"", file=sys.stderr)
    print("3. Invalid Domain: curl -v \"http://localhost:8080/redirect?url=http%3A%2F%2Fgoogle.com\"", file=sys.stderr)
    print("4. Invalid Subdomain Attack: curl -v \"http://localhost:8080/redirect?url=http%3A%2F%2Fexample.com.evil.com\"", file=sys.stderr)
    print("5. Malformed URL: curl -v \"http://localhost:8080/redirect?url=not_a_valid_url\"", file=sys.stderr)
    
    # In a production environment, use a proper WSGI server instead of app.run.
    app.run(host='0.0.0.0', port=port)

if __name__ == '__main__':
    main()