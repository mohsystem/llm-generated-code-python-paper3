
from urllib.parse import urlparse

def redirect_url(url):
    parsed_url = urlparse(url)
    network_location = parsed_url.netloc
    
    if network_location == "example.com":
        return f"Redirect to: {url}"
    else:
        return "404 Error: Domain not allowed"

if __name__ == "__main__":
    # Test cases
    print(redirect_url("http://example.com/page"))
    print(redirect_url("https://example.com/admin"))
    print(redirect_url("http://notexample.com/page"))
    print(redirect_url("https://evil.com/phishing"))
    print(redirect_url("http://example.com:8080/secure"))
