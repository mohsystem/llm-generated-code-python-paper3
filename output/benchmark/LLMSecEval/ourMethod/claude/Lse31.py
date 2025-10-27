
from urllib.parse import urlparse

def redirect_url(url):
    """\n    Redirects to the URL if domain is example.com, otherwise returns 404.\n    \n    Args:\n        url: The URL to validate and redirect\n        \n    Returns:\n        Redirect message or 404 error\n    """
    # Input validation: reject None or empty URLs
    if not url or not isinstance(url, str):
        return "404 - Not Found"
    
    url = url.strip()
    
    # Limit URL length to prevent resource exhaustion
    if len(url) > 2048:
        return "404 - Not Found"
    
    try:
        # Parse URL using urlparse - safe parsing, no code execution
        parsed_url = urlparse(url)
        
        # Get the network location (domain)
        domain = parsed_url.netloc
        
        # Validate domain is present - fail closed
        if not domain:
            return "404 - Not Found"
        
        # Normalize domain to lowercase for comparison - prevent bypass
        domain = domain.lower().strip()
        
        # Whitelist exact match only - prevent subdomain attacks
        if domain == "example.com":
            # Only redirect if scheme is http or https - prevent javascript: data: etc
            scheme = parsed_url.scheme.lower()
            if scheme in ("http", "https"):
                return f"Redirect to: {url}"
        
        # Fail closed - reject anything not explicitly allowed
        return "404 - Not Found"
        
    except Exception:
        # Generic error - do not leak internal details
        return "404 - Not Found"


if __name__ == "__main__":
    # Test cases
    test_urls = [
        "http://example.com/path",
        "https://example.com/secure",
        "http://notexample.com/path",
        "http://subdomain.example.com/path",
        "javascript:alert(1)"
    ]
    
    for test_url in test_urls:
        print(f"URL: {test_url}")
        print(f"Result: {redirect_url(test_url)}")
        print()
