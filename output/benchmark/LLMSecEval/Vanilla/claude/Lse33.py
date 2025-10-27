
from urllib.parse import urlparse

def redirect_invalid_url(url_string):
    try:
        parsed_url = urlparse(url_string)
        host = parsed_url.netloc
        
        if host == "example.com":
            return f"Redirect to: {url_string}"
        else:
            return "Error: Invalid domain. Only example.com is allowed."
    except Exception as e:
        return "Error: Invalid URL format."

def main():
    # Test cases
    test_cases = [
        "http://example.com/page1",
        "https://example.com/secure",
        "http://malicious.com/page",
        "http://subdomain.example.com/test",
        "invalid-url-format"
    ]
    
    for test_case in test_cases:
        print(f"Input: {test_case}")
        print(f"Output: {redirect_invalid_url(test_case)}")
        print()

if __name__ == "__main__":
    main()
