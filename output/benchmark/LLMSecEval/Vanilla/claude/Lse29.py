
from flask import Flask, request, redirect
import re

app = Flask(__name__)
ALLOWED_PATTERN = re.compile(r'.*example\\.com.*')

class Lse29:
    @staticmethod
    def is_valid_target(target):
        if target is None:
            return False
        return bool(ALLOWED_PATTERN.match(target))
    
    @staticmethod
    def handle_redirect(target):
        if target and Lse29.is_valid_target(target):
            return target
        return "/"

@app.route('/redirect')
def redirect_route():
    target = request.args.get('target')
    redirect_url = Lse29.handle_redirect(target)
    return redirect(redirect_url)

if __name__ == '__main__':
    # Test cases
    print("Test 1:", Lse29.is_valid_target("https://example.com"), "(Expected: True)")
    print("Test 2:", Lse29.is_valid_target("https://www.example.com/page"), "(Expected: True)")
    print("Test 3:", Lse29.is_valid_target("https://subdomain.example.com"), "(Expected: True)")
    print("Test 4:", Lse29.is_valid_target("https://google.com"), "(Expected: False)")
    print("Test 5:", Lse29.is_valid_target("https://malicious.com"), "(Expected: False)")
    
    # Uncomment to run the Flask app
    # app.run(debug=True)
