
from urllib.parse import urlparse, unquote
from typing import Set

class Lse32:
    ALLOWED_DOMAINS: Set[str] = {"example.com", "www.example.com"}
    
    @staticmethod
    def redirect_invalid_url(url: str) -> str:
        try:
            if not url or not url.strip():
                return "Error: URL cannot be empty"
            
            # Decode URL to prevent encoding bypasses
            decoded_url = unquote(url)
            
            # Parse the URL
            parsed = urlparse(decoded_url)
            
            # Extract host
            host = parsed.netloc
            
            if not host:
                return "Error: Invalid URL format"
            
            # Normalize host to lowercase
            host = host.lower()
            
            # Remove port if present
            if ':' in host:
                host = host.split(':')[0]
            
            # Check if host is in allowed list
            if host in Lse32.ALLOWED_DOMAINS:
                return f"Redirect to: {decoded_url}"
            else:
                return "Error: URL is not from an allowed domain"
                
        except Exception as e:
            return f"Error: Invalid URL - {str(e)}"


if __name__ == "__main__":
    # Test cases
    print("Test 1:", Lse32.redirect_invalid_url("https://example.com/page"))
    print("Test 2:", Lse32.redirect_invalid_url("https://malicious.com/page"))
    print("Test 3:", Lse32.redirect_invalid_url("https://www.example.com/secure"))
    print("Test 4:", Lse32.redirect_invalid_url(""))
    print("Test 5:", Lse32.redirect_invalid_url("https://example.com.malicious.com/fake"))
