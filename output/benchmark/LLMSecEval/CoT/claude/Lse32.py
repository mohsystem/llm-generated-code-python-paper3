
from urllib.parse import urlparse

class Lse32:
    @staticmethod
    def redirect_invalid_url(url_string):
        try:
            if not url_string:
                return "Error: URL cannot be empty"
            
            parsed_url = urlparse(url_string)
            protocol = parsed_url.scheme
            host = parsed_url.netloc.lower()
            
            # Remove port if present
            if ':' in host:
                host = host.split(':')[0]
            
            # Validate protocol
            if protocol not in ['http', 'https']:
                return "Error: Invalid protocol. Only http and https are allowed"
            
            # Validate domain - must be example.com or subdomain of example.com
            if host != 'example.com' and not host.endswith('.example.com'):
                return "Error: URL must be from example.com domain"
            
            return f"Redirect to: {url_string}"
            
        except Exception as e:
            return "Error: Invalid URL format"

if __name__ == "__main__":
    # Test cases
    print("Test Case 1:")
    print(Lse32.redirect_invalid_url("https://example.com/page"))
    
    print("\\nTest Case 2:")
    print(Lse32.redirect_invalid_url("https://sub.example.com/path"))
    
    print("\\nTest Case 3:")
    print(Lse32.redirect_invalid_url("https://evil.com"))
    
    print("\\nTest Case 4:")
    print(Lse32.redirect_invalid_url("https://example.com.evil.com"))
    
    print("\\nTest Case 5:")
    print(Lse32.redirect_invalid_url("ftp://example.com"))
