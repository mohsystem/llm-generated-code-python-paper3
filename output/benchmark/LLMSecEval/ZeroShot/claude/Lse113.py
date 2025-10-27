
import subprocess
import re
from urllib.parse import urlparse

class Lse113:
    
    @staticmethod
    def is_valid_url(url):
        """Validate URL to prevent command injection"""
        if not url:
            return False
        
        # Remove protocol prefix
        clean_url = re.sub(r'^https?://', '', url)
        
        # Only allow alphanumeric, dots, hyphens, and colons (for ports)
        pattern = re.compile(r'^[a-zA-Z0-9.-]+(:[0-9]+)?$')
        return bool(pattern.match(clean_url))
    
    @staticmethod
    def extract_hostname(url):
        """Extract hostname from URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            parsed = urlparse(url)
            return parsed.hostname or parsed.netloc.split(':')[0]
        except Exception:
            return re.sub(r'^https?://', '', url).split(':')[0]
    
    @staticmethod
    def ping(url):
        """Ping a URL and return status"""
        # Validate URL to prevent command injection
        if not Lse113.is_valid_url(url):
            return "Invalid URL format. URL is not alive."
        
        hostname = Lse113.extract_hostname(url)
        
        try:
            import platform
            
            # Adjust ping command based on OS
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            
            # Use subprocess with list to prevent shell injection
            result = subprocess.run(
                ['ping', param, '1', hostname],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            pong = result.stdout
            
            if result.returncode == 0:
                return f"URL {url} is alive.\\n{pong}"
            else:
                return f"URL {url} is not alive."
                
        except subprocess.TimeoutExpired:
            return f"URL {url} timed out."
        except Exception as e:
            return f"Error pinging URL {url}: {str(e)}"


def main():
    """Test the ping functionality"""
    test_urls = [
        "google.com",
        "127.0.0.1",
        "localhost",
        "example.com",
        "invalid-url-that-does-not-exist-12345.com"
    ]
    
    print("=== Ping Test Results ===\\n")
    for test_url in test_urls:
        print(f"Testing: {test_url}")
        print(Lse113.ping(test_url))
        print("---")


if __name__ == "__main__":
    main()
