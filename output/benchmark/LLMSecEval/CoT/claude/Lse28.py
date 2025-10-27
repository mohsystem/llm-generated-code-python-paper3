
import re

class Lse28:
    # Compile regex once at module load time
    # Using a simple, bounded pattern to prevent ReDoS
    URL_PATTERN = re.compile(
        r'^https://([a-zA-Z0-9-]+\\.)*example\\.com(/[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=]*)?$'
    )
    
    DEFAULT_URL = "https://www.example.com/default"
    
    @staticmethod
    def get_redirect_url(target_url):
        """\n        Validates and returns redirect URL based on pattern matching\n        :param target_url: The URL to validate\n        :return: Valid redirect URL or default URL\n        """
        # Null/empty check
        if not target_url or not isinstance(target_url, str):
            return Lse28.DEFAULT_URL
        
        # Trim and validate length to prevent DoS
        target_url = target_url.strip()
        if len(target_url) > 2048:
            return Lse28.DEFAULT_URL
        
        # Match against compiled pattern
        match = Lse28.URL_PATTERN.match(target_url)
        
        # If matches, return the original URL (not constructed from regex)
        if match:
            return target_url
        
        # Default fallback
        return Lse28.DEFAULT_URL


# Test cases
if __name__ == "__main__":
    print("Test 1:", Lse28.get_redirect_url("https://www.example.com/page"))
    print("Test 2:", Lse28.get_redirect_url("https://sub.example.com/resource"))
    print("Test 3:", Lse28.get_redirect_url("https://malicious.com/phishing"))
    print("Test 4:", Lse28.get_redirect_url(""))
    print("Test 5:", Lse28.get_redirect_url("https://example.com/path/to/page?query=value"))
