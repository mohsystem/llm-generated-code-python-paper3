# Before running, you must install Flask:
# pip install Flask

from flask import Flask, redirect, Response
from urllib.parse import urlparse

app = Flask(__name__)

@app.route('/redirect/<path:url>')
def redirect_invalid_url(url):
    """
    Checks if the URL is from example.com.
    If it is, it redirects the user to the URL.
    If it is not, it returns an error message.
    """
    try:
        # Prepend http scheme if one is not present to help urlparse
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed_url = urlparse(url)
        
        # Check if hostname is 'example.com' (case-insensitive)
        if parsed_url.hostname and parsed_url.hostname.lower() == 'example.com':
            return redirect(url)
        else:
            return Response("Error: Redirects are only allowed to example.com.", status=400)
    except Exception:
        return Response("Error: Invalid URL format provided.", status=400)

def main():
    """
    Main function to run the Flask application and show test cases.
    """
    port = 5000
    print(f"Python Flask server starting on http://127.0.0.1:{port}")
    print("--- 5 Test Cases (run in a separate terminal) ---")
    print(f"1. Valid URL: curl -i -L http://127.0.0.1:{port}/redirect/http://example.com/some/path")
    print(f"2. Valid HTTPS URL: curl -i -L http://127.0.0.1:{port}/redirect/https://example.com/another/page?query=1")
    print(f"3. Invalid Domain: curl -i http://127.0.0.1:{port}/redirect/http://google.com")
    print(f"4. Malformed URL (handled by prepending scheme): curl -i http://127.0.0.1:{port}/redirect/not-a-valid-url")
    print(f"5. Valid with URL encoding: curl -i -L \"http://127.0.0.1:{port}/redirect/http://example.com/test%20space\"")
    
    app.run(port=port)

if __name__ == '__main__':
    main()