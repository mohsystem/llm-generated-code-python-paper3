
from urllib.parse import urlparse

def redirect_url(url):
    if not url or not isinstance(url, str) or not url.strip():
        return "404 Error: Invalid URL"
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Remove port if present for exact domain comparison
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Exact domain match (case-insensitive) - no subdomains allowed
        if domain.lower() == "example.com":
            return f"Redirect to: {url}"
        else:
            return "404 Error: Domain not allowed"
    except Exception as e:
        return "404 Error: Invalid URL format"

# Test cases
if __name__ == "__main__":
    print("Test 1:", redirect_url("http://example.com/path"))
    print("Test 2:", redirect_url("https://example.com/secure"))
    print("Test 3:", redirect_url("http://evil.com/malicious"))
    print("Test 4:", redirect_url("http://subdomain.example.com/path"))
    print("Test 5:", redirect_url("invalid-url"))
