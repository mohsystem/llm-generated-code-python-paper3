from urllib.parse import urlparse

def redirect_url(url: str) -> str:
    """
    Checks the domain of a URL and returns a redirect or 404 message.

    Args:
        url: The URL string to check.

    Returns:
        A string indicating redirection or a 404 error.
    """
    if not isinstance(url, str) or not url:
        return "404 Not Found"
    
    try:
        # urlparse is generally safe and handles malformed URLs gracefully
        parsed_url = urlparse(url)
        # We use .hostname to get just the domain without the port
        domain = parsed_url.hostname
        
        if domain and domain == "example.com":
            return f"Redirecting to {url}"
        else:
            return "404 Not Found"
    except Exception:
        # Catch any unexpected errors during parsing
        return "404 Not Found"

def main():
    """Main function with test cases."""
    test_cases = [
        "https://example.com/some/path",  # Case 1: Match
        "http://google.com/search",       # Case 2: No Match
        "invalid-url-format",             # Case 3: Invalid format (urlparse handles it)
        "https://another-site.net",       # Case 4: Another No Match
        "http://example.com"              # Case 5: Match without path
    ]
    
    print("--- Running 5 Test Cases ---")
    for url in test_cases:
        print(f"Input: {url}")
        print(f"Output: {redirect_url(url)}")
        print("--------------------")

if __name__ == "__main__":
    main()