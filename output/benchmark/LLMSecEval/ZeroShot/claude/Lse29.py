
import re
from flask import Flask, request, redirect

app = Flask(__name__)
ALLOWED_URL_PATTERN = re.compile(r'^https?://([a-zA-Z0-9-]+\\.)*example\\.com(/.*)?$')

def is_valid_target(target):
    if not target:
        return False
    return bool(ALLOWED_URL_PATTERN.match(target))

def get_redirect_url(target):
    if is_valid_target(target):
        return target
    return '/'

@app.route('/')
def redirect_route():
    target = request.args.get('target', '')
    redirect_url = get_redirect_url(target)
    return redirect(redirect_url)

def main():
    # Test cases
    test_cases = [
        "http://example.com",
        "https://subdomain.example.com/path",
        "http://malicious.com",
        "https://example.com.malicious.com",
        None
    ]
    
    print("Test Results:")
    for i, test in enumerate(test_cases, 1):
        result = get_redirect_url(test)
        print(f"Test Case {i}: Input: {test} -> Output: {result}")

if __name__ == '__main__':
    main()
    # Uncomment to run the Flask app
    # app.run(debug=True)
