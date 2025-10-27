from flask import Flask, redirect, abort, Response
from urllib.parse import urlparse

app = Flask(__name__)

def redirect_invalid_url(url: str) -> Response:
    """
    Checks if the URL is from example.com and returns a redirect response if valid.
    Otherwise, it aborts the request with a 400 error.
    """
    try:
        # Rule #1: Validate and sanitize input
        # urlparse is used to break the URL into components.
        parsed_url = urlparse(url)

        # Security: Check if the scheme is either http or https. This prevents
        # redirection to other schemes like 'javascript:' or 'file:'.
        if parsed_url.scheme not in ('http', 'https'):
            abort(400, description="Invalid URL scheme. Only http and https are allowed.")

        # Security: Check if the hostname is exactly 'example.com'.
        # This prevents open redirect vulnerabilities (CWE-601).
        if parsed_url.hostname != 'example.com':
            abort(400, description="Invalid domain. Redirects are only allowed to example.com.")
        
        # If all checks pass, return a redirect response.
        return redirect(url)

    except ValueError:
        # This can be triggered by malformed URLs containing characters
        # that urlparse cannot handle, like null bytes.
        abort(400, description="Malformed URL provided.")

@app.route('/redirect/<path:url>')
def redirect_handler(url: str) -> Response:
    # Flask's <path:url> converter automatically handles URL decoding.
    return redirect_invalid_url(url)

if __name__ == '__main__':
    print("Starting Flask server on http://127.0.0.1:5000")
    print("Use Ctrl+C to stop the server.")
    print("\n--- Test Cases (run in a separate terminal) ---")
    print("1. Valid HTTP redirect: curl -iL \"http://127.0.0.1:5000/redirect/http%3A%2F%2Fexample.com\"")
    print("2. Valid HTTPS redirect with path: curl -iL \"http://127.0.0.1:5000/redirect/https%3A%2F%2Fexample.com%2Fsome%2Fpath\"")
    print("3. Invalid domain: curl -i \"http://127.0.0.1:5000/redirect/http%3A%2F%2Fevil.com\"")
    print("4. Invalid scheme: curl -i \"http://127.0.0.1:5000/redirect/javascript:alert('xss')\"")
    print("5. Malformed URL (not a valid URL structure): curl -i \"http://127.0.0.1:5000/redirect/not-a-valid-url\"")
    print("-------------------------------------------------\n")
    # Note: Use a production-ready WSGI server like Gunicorn or uWSGI in production.
    app.run(host='127.0.0.1', port=5000, debug=False)