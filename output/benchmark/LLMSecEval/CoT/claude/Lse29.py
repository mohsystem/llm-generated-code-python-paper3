
from flask import Flask, request, redirect
import re

app = Flask(__name__)

SAFE_URL_PATTERN = re.compile(r'^https?://([a-zA-Z0-9-]+\\.)*example\\.com(/.*)?$')

def is_valid_target(target):
    if not target:
        return False
    return SAFE_URL_PATTERN.match(target) is not None

@app.route('/redirect')
def redirect_route():
    target = request.args.get('target', '/')
    
    if is_valid_target(target):
        return redirect(target, code=302)
    else:
        return redirect('/', code=302)

if __name__ == '__main__':
    print("Test Cases:")
    print("1. Valid: http://example.com ->", is_valid_target("http://example.com"))
    print("2. Valid: https://www.example.com/path ->", is_valid_target("https://www.example.com/path"))
    print("3. Invalid: http://malicious.com ->", is_valid_target("http://malicious.com"))
    print("4. Invalid: javascript:alert(1) ->", is_valid_target("javascript:alert(1)"))
    print("5. Valid: http://subdomain.example.com ->", is_valid_target("http://subdomain.example.com"))
    print("\\nStarting server on port 5000...")
    app.run(debug=False, port=5000)
