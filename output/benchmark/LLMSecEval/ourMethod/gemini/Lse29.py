import re
from flask import Flask, request, redirect, Response

app = Flask(__name__)

# A regex that matches URLs where the host contains "example.com".
# This is a safer interpretation of "contains example.com" to prevent open redirects.
ALLOWED_DOMAIN_REGEX = re.compile(r'^https?://[^/]*example\.com.*')

def get_redirect_url(target):
    """
    Checks if the target URL is valid according to the regex.
    Returns the target if valid, otherwise returns the root path '/'.
    """
    if target and ALLOWED_DOMAIN_REGEX.match(target):
        return target
    return '/'

@app.route('/')
def handle_redirect():
    """
    Handles requests. If a 'target' parameter is provided and valid,
    it redirects to it. Otherwise, it shows a simple home page.
    """
    target = request.args.get('target')
    redirect_url = get_redirect_url(target)

    if redirect_url == '/':
        # For invalid or missing targets, show a simple homepage to avoid a redirect loop.
        return Response(
            "Welcome. Provide a valid 'target' parameter pointing to a URL "
            "at example.com to be redirected.",
            mimetype='text/plain'
        )
    else:
        return redirect(redirect_url)

def run_tests():
    """Runs 5 test cases against the redirection logic."""
    print("\n--- Running 5 Test Cases ---")
    
    # Test Case 1: Valid URL
    test1 = "http://example.com"
    print(f"1. (Valid) {test1} -> {get_redirect_url(test1)}")

    # Test Case 2: Valid URL with subdomain and path
    test2 = "http://sub.example.com/some/path"
    print(f"2. (Valid) {test2} -> {get_redirect_url(test2)}")
    
    # Test Case 3: Invalid domain
    test3 = "http://another-domain.com"
    print(f"3. (Invalid) {test3} -> {get_redirect_url(test3)}")

    # Test Case 4: Invalid URL with tricky parameter
    test4 = "http://evil.com/?q=example.com"
    print(f"4. (Invalid) {test4} -> {get_redirect_url(test4)}")
    
    # Test Case 5: None target
    print(f"5. (None target) None -> {get_redirect_url(None)}")

    print("--- Test Cases Finished ---\n")

if __name__ == '__main__':
    run_tests()
    print("Starting Flask server on http://127.0.0.1:5000")
    print("Test with a browser, e.g., http://127.0.0.1:5000/?target=http://example.com")
    app.run(host="0.0.0.0", port=5000)