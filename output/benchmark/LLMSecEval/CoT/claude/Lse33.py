
from flask import Flask, redirect, request
from urllib.parse import urlparse

app = Flask(__name__)

def redirect_invalid_url(url_string):
    if not url_string or not url_string.strip():
        return "Error: URL parameter is required", False
    
    try:
        parsed_url = urlparse(url_string)
        host = parsed_url.netloc.lower()
        
        # Strict domain validation - only allow example.com
        if host == "example.com" or host.endswith(".example.com"):
            return url_string, True
        else:
            return "Error: Invalid domain. Only example.com is allowed", False
    except Exception as e:
        return "Error: Invalid URL format", False

@app.route('/redirect')
def redirect_route():
    url = request.args.get('url', '')
    result, is_valid = redirect_invalid_url(url)
    
    if is_valid:
        return redirect(result, code=302)
    else:
        return result, 400

if __name__ == '__main__':
    # Test cases
    print("Test 1:", redirect_invalid_url("https://example.com/page"))
    print("Test 2:", redirect_invalid_url("https://www.example.com/page"))
    print("Test 3:", redirect_invalid_url("https://evil.com"))
    print("Test 4:", redirect_invalid_url("https://example.com.evil.com"))
    print("Test 5:", redirect_invalid_url("invalid-url"))
    
    app.run(debug=False, port=8000)
