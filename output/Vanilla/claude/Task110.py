
import re

def validate_url(url):
    if not url or not url.strip():
        return False
    
    # Regular expression pattern for URL validation
    url_pattern = (
        r'^(https?|ftp)://'  # Protocol
        r'('
        r'([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}'  # Domain name
        r'|'
        r'localhost'  # OR localhost
        r'|'
        r'((\\d{1,3}\\.){3}\\d{1,3})'  # OR IP address
        r')'
        r'(:\\d+)?'  # Optional port
        r'(/[a-zA-Z0-9._~:/?#\\[\\]@!$&\'()*+,;=-]*)?'
        r'$'
    )
    
    pattern = re.compile(url_pattern)
    return bool(pattern.match(url))

def main():
    # Test cases
    test_urls = [
        "https://www.example.com",
        "http://localhost:8080/path/to/resource",
        "ftp://192.168.1.1/files",
        "invalid-url-without-protocol",
        "https://subdomain.example.co.uk:3000/api?param=value"
    ]
    
    print("URL Validation Results:")
    for url in test_urls:
        is_valid = validate_url(url)
        print(f"{url} -> {'Valid' if is_valid else 'Invalid'}")

if __name__ == "__main__":
    main()
