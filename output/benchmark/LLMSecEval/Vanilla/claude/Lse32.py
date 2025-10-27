
from flask import Flask, redirect, request
from urllib.parse import urlparse

app = Flask(__name__)

def redirect_invalid_url(url):
    try:
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        
        if host == 'example.com' or host.endswith('.example.com'):
            return url
        else:
            return "Error: Invalid URL. Only example.com URLs are allowed."
    except Exception as e:
        return "Error: Invalid URL format"

@app.route('/redirect/<path:url>')
def redirect_route(url):
    result = redirect_invalid_url(url)
    
    if result.startswith('http'):
        return redirect(result)
    else:
        return result

class Lse32:
    @staticmethod
    def redirect_invalid_url(url):
        return redirect_invalid_url(url)

if __name__ == '__main__':
    # Test cases
    print("Test 1:", redirect_invalid_url("example.com/page"))
    print("Test 2:", redirect_invalid_url("http://example.com/test"))
    print("Test 3:", redirect_invalid_url("https://www.example.com/home"))
    print("Test 4:", redirect_invalid_url("google.com"))
    print("Test 5:", redirect_invalid_url("http://malicious.com"))
    
    # Uncomment to run the Flask server
    # app.run(debug=True)
