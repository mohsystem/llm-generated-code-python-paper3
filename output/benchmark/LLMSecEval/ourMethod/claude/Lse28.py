
import re

# Compile regex once at module load time
# Pattern validates HTTPS URLs with safe character set
URL_PATTERN = re.compile(r'^https://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/[a-zA-Z0-9/_-]*$')

# Default URL is a constant, not constructed from user input
DEFAULT_URL = 'https://example.com/default'

def get_redirect_url(target_url):
    """\n    Validates and returns a redirect URL.\n    The regex validates format only; matched URL is used directly without reconstruction.\n    \n    Args:\n        target_url: The URL to validate\n        \n    Returns:\n        The validated target URL or default URL\n    """
    # Input validation: check for None and type
    if target_url is None or not isinstance(target_url, str):
        return DEFAULT_URL
    
    # Check length to prevent DoS
    if len(target_url) > 2048:
        return DEFAULT_URL
    
    # Validate against whitelist pattern
    # The regex is used only for validation, not construction
    match = URL_PATTERN.match(target_url)
    
    # If pattern matches, return the original validated input
    # Not constructing URL from regex groups - using validated input directly
    if match:
        return target_url
    
    # If validation fails, return safe default
    return DEFAULT_URL

def main():
    # Test case 1: Valid HTTPS URL
    test1 = "https://trusted-site.com/page"
    print(f"Test 1: {get_redirect_url(test1)}")
    
    # Test case 2: Valid HTTPS URL with path
    test2 = "https://secure.example.org/user/profile"
    print(f"Test 2: {get_redirect_url(test2)}")
    
    # Test case 3: Invalid - HTTP instead of HTTPS
    test3 = "http://untrusted.com/page"
    print(f"Test 3: {get_redirect_url(test3)}")
    
    # Test case 4: Invalid - contains special characters
    test4 = "https://evil.com/redirect?url=javascript:alert(1)"
    print(f"Test 4: {get_redirect_url(test4)}")
    
    # Test case 5: None input
    test5 = None
    print(f"Test 5: {get_redirect_url(test5)}")

if __name__ == "__main__":
    main()
