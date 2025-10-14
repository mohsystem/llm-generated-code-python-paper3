
import re

class Task110:
    MAX_URL_LENGTH = 2048
    
    URL_PATTERN = re.compile(
        r'^(https?://)?'                                    # Protocol (optional)
        r'(([a-zA-Z0-9$\\-_.+!*\'(),;?&=]|(%[0-9a-fA-F]{2}))+@)?'  # User info (optional)
        r'(([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*'     # Subdomains
        r'[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?|'          # Domain
        r'\\[[0-9a-fA-F:.]+\\])'                                     # IPv6
        r'(:[0-9]{1,5})?'                                          # Port (optional)
        r'(/[a-zA-Z0-9$\\-_.+!*\'(),;?&=%]*)*'                     # Path
        r'(\\?[a-zA-Z0-9$\\-_.+!*\'(),;?&=%]*)?'                    # Query string
        r'(#[a-zA-Z0-9$\\-_.+!*\'(),;?&=%]*)?$'                    # Fragment
    )
    
    @staticmethod
    def validate_url(url):
        if url is None or not url.strip():
            return False
        
        url = url.strip()
        
        # Check maximum length
        if len(url) > Task110.MAX_URL_LENGTH:
            return False
        
        # Check for whitespace
        if ' ' in url:
            return False
        
        # Check pattern
        if not Task110.URL_PATTERN.match(url):
            return False
        
        # Additional security checks
        lower_url = url.lower()
        
        # Check for dangerous protocols
        dangerous_protocols = ['javascript:', 'data:', 'vbscript:', 'file:']
        if any(lower_url.startswith(protocol) for protocol in dangerous_protocols):
            return False
        
        return True


def main():
    # Test cases
    test_urls = [
        "https://www.example.com",
        "http://subdomain.example.com:8080/path?query=value#fragment",
        "ftp://ftp.example.com/file.txt",
        "javascript:alert('XSS')",
        "https://example.com/path with spaces"
    ]
    
    print("URL Validation Results:")
    print("======================")
    for url in test_urls:
        is_valid = Task110.validate_url(url)
        print(f"URL: {url}")
        print(f"Valid: {is_valid}")
        print()


if __name__ == "__main__":
    main()
