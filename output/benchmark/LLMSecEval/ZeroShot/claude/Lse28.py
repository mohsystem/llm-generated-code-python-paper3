
import re

# Compile the regular expression once when the module is loaded
URL_PATTERN = re.compile(r'^https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/.*)?$')
DEFAULT_URL = "https://default.example.com"

def get_redirect_url(target_url):
    if not target_url:
        return DEFAULT_URL
    
    # If the target URL matches the pattern, use it as redirect target
    if URL_PATTERN.match(target_url):
        return target_url
    
    # If the target URL does not match, use default URL
    return DEFAULT_URL

def main():
    # Test cases
    test_cases = [
        "https://www.example.com/page",
        "http://test.com",
        "invalid-url",
        "ftp://wrong-protocol.com",
        "https://secure-site.org/path/to/resource"
    ]
    
    print("Testing URL Redirect Logic:")
    for test_url in test_cases:
        result = get_redirect_url(test_url)
        print(f"Input: {test_url} -> Redirect: {result}")

if __name__ == "__main__":
    main()
