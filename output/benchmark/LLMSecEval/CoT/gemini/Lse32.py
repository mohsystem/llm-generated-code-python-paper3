# To run this code, you need to install Flask:
# pip install Flask
from flask import Flask, redirect, abort
from urllib.parse import urlparse

app = Flask(__name__)

def redirect_invalid_url(url: str):
    """
    Checks if a URL is from example.com and returns a redirect response.
    Otherwise, it aborts with a 400 error.
    """
    try:
        # Use robust parsing from urllib.parse
        parsed_url = urlparse(url)
        
        # Security Check: Ensure the URL has a scheme and the hostname is 'example.com'
        if parsed_url.scheme in ['http', 'https'] and parsed_url.hostname == 'example.com':
            # Safe to redirect
            return redirect(url)
        else:
            # Disallowed host or malformed URL
            abort(400, "Invalid URL. Only redirects to example.com are allowed.")
            
    except Exception:
        # Catch any other parsing errors
        abort(400, "Malformed URL provided.")


# The route captures the full URL path, including slashes
@app.route('/redirect/<path:url>')
def redirect_route(url):
    return redirect_invalid_url(url)

if __name__ == '__main__':
    port = 5000
    print(f"Python Flask server running on port {port}")
    print("Test with the following URLs:")
    print(f"1. Valid: http://127.0.0.1:{port}/redirect/http://example.com")
    print(f"2. Valid with path: http://127.0.0.1:{port}/redirect/https://example.com/some/path")
    print(f"3. Invalid Host: http://127.0.0.1:{port}/redirect/http://google.com")
    print(f"4. Tricky URL (invalid): http://127.0.0.1:{port}/redirect/http://example.com@evil.com")
    print(f"5. Malformed URL: http://127.0.0.1:{port}/redirect/not-a-valid-url")
    
    # Setting debug=False for a more secure default, though debug is useful for development
    app.run(port=port, debug=False)