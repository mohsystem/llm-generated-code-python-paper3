
import re

# Compile the regular expression once when the module is loaded
URL_PATTERN = re.compile(r'^https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/.*)?$')
DEFAULT_URL = "https://www.default.com"

def get_redirect_url(target_url):
    """\n    Checks if the target URL matches the pattern.\n    Returns the target URL if it matches, otherwise returns the default URL.\n    """
    # If the target URL matches the pattern, use it as redirect target
    if URL_PATTERN.match(target_url):
        return target_url
    
    # If the target URL does not match, use default URL
    return DEFAULT_URL

if __name__ == "__main__":
    # Test case 1: Valid HTTP URL
    print("Test 1:", get_redirect_url("http://www.example.com"))
    
    # Test case 2: Valid HTTPS URL with path
    print("Test 2:", get_redirect_url("https://www.example.com/path/to/page"))
    
    # Test case 3: Valid URL with subdomain
    print("Test 3:", get_redirect_url("https://subdomain.example.com"))
    
    # Test case 4: Invalid URL (missing protocol)
    print("Test 4:", get_redirect_url("www.example.com"))
    
    # Test case 5: Invalid URL (random text)
    print("Test 5:", get_redirect_url("not-a-valid-url"))
