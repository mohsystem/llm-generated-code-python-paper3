# To run this code, you need to install Flask:
# pip install Flask
from flask import Flask, request, redirect, Response
from urllib.parse import urlparse

app = Flask(__name__)

def redirect_invalid_url(target_url):
    """
    Checks if the URL has the domain "example.com".
    If it is, returns a redirect response.
    If it is not, returns an error message and a 400 status code.
    
    :param target_url: The URL to validate and redirect to.
    :return: A Flask Response object (either a redirect or an error).
    """
    if not target_url:
        return Response("Error: URL parameter is missing.", status=400)

    try:
        # Use urlparse for robust parsing to prevent parsing exploits
        parsed_url = urlparse(target_url)
        
        # Secure check: The scheme must be http or https, and the netloc (domain)
        # must be exactly 'example.com'. This prevents open redirect vulnerabilities.
        if parsed_url.scheme in ['http', 'https'] and parsed_url.netloc == 'example.com':
            return redirect(target_url)
        else:
            return Response("Error: Invalid domain. Redirection is only allowed to example.com.", status=400)
            
    except Exception:
        return Response("Error: Malformed URL provided.", status=400)

@app.route('/redirect')
def handle_redirect():
    url_param = request.args.get('url')
    return redirect_invalid_url(url_param)

def main():
    """
    Main function to run the Flask application and provide test cases.
    """
    port = 8080
    print(f"Starting server on port {port}")
    print("Use a browser or curl to test the /redirect endpoint.")
    print("\n--- Test Cases ---")
    print("1. Valid URL (should redirect):")
    print(f"   curl -I \"http://localhost:{port}/redirect?url=http://example.com/test\"")
    print("\n2. Invalid Domain (should return 400 error):")
    print(f"   curl \"http://localhost:{port}/redirect?url=http://google.com\"")
    print("\n3. Invalid Subdomain Exploit Attempt (should return 400 error):")
    print(f"   curl \"http://localhost:{port}/redirect?url=http://example.com.malicious.com\"")
    print("\n4. Missing URL parameter (should return 400 error):")
    print(f"   curl \"http://localhost:{port}/redirect\"")
    print("\n5. Malformed URL with different scheme (should return 400 error):")
    print(f"   curl \"http://localhost:{port}/redirect?url=ftp://example.com\"")

    # In a real scenario, you would run the app like this:
    # app.run(host='0.0.0.0', port=port)
    # For this example, we just print the test instructions.
    
if __name__ == '__main__':
    # We call main to print test cases, but to run the server,
    # you would typically run `flask run` or uncomment the line in main().
    main()
    # To actually run the server for testing:
    # app.run(port=8080)