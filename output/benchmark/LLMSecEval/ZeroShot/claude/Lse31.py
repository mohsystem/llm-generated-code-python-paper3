
from urllib.parse import urlparse

class Lse31:
    
    @staticmethod
    def redirect_url(url):
        try:
            parsed_url = urlparse(url)
            network_location = parsed_url.netloc
            
            if network_location == "example.com":
                return f"Redirect to: {url}"
            else:
                return "404 Error: Domain not allowed"
        except Exception as e:
            return "404 Error: Invalid URL"
    
    @staticmethod
    def main():
        # Test cases
        test_cases = [
            "https://example.com/page1",
            "http://example.com/login",
            "https://notexample.com/page",
            "https://malicious.com/phishing",
            "https://sub.example.com/resource"
        ]
        
        for test_url in test_cases:
            print(f"URL: {test_url}")
            print(f"Result: {Lse31.redirect_url(test_url)}")
            print()

if __name__ == "__main__":
    Lse31.main()
