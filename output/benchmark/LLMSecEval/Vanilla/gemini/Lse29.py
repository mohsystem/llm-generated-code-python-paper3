# Note: This code requires the Flask library.
# Install it with: pip install Flask

import re
from flask import Flask, request, redirect, url_for

# The concept of a single main class 'Lse29' is not idiomatic in Flask.
# The Flask 'app' object serves as the central point of the application.
app = Flask(__name__)

@app.route('/')
def index():
    """Handler for the root URL."""
    return 'Welcome! This is the default page.', 200

@app.route('/redirect')
def redirect_handler():
    """
    Redirects to a 'target' URL if it contains 'example.com',
    otherwise redirects to the root page.
    """
    target = request.args.get('target')
    regex = r".*example\.com.*"
    
    if target and re.match(regex, target):
        return redirect(target, code=302)
    else:
        return redirect(url_for('index'), code=302)
        
def main():
    """Main function to run the server and print test cases."""
    port = 5000
    base_url = f"http://127.0.0.1:{port}"
    print(f"Python Flask server started on {base_url}")
    print("--- 5 Test Cases ---")
    print("Execute these commands in a separate terminal:")
    print(f"1. Valid Target: curl -I \"{base_url}/redirect?target=http://www.example.com\"")
    print("   Expected: 302 Redirect to http://www.example.com")
    print(f"2. Valid Subdomain: curl -I \"{base_url}/redirect?target=https://blog.example.com/article/1\"")
    print("   Expected: 302 Redirect to https://blog.example.com/article/1")
    print(f"3. Invalid Target: curl -I \"{base_url}/redirect?target=http://www.google.com\"")
    print("   Expected: 302 Redirect to /")
    print(f"4. Invalid TLD: curl -I \"{base_url}/redirect?target=http://example.community.net\"")
    print("   Expected: 302 Redirect to /")
    print(f"5. Missing Target: curl -I \"{base_url}/redirect\"")
    print("   Expected: 302 Redirect to /")
    
    app.run(port=port, debug=False)

if __name__ == '__main__':
    main()