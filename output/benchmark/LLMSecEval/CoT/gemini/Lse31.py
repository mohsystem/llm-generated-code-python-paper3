from urllib.parse import urlparse

def redirect_url(url: str) -> str:
    """
    Checks if a URL's domain is 'example.com' and returns a corresponding status message.
    :param url: The URL to check.
    :return: A string indicating redirection or a 404 error.
    """
    try:
        # Ensure input is a string to prevent errors with urlparse
        if not isinstance(url, str):
            return "404 Not Found"
            
        parsed_url = urlparse(url)
        # parsed_url.scheme ensures it's an absolute URL (e.g., http, https)
        # parsed_url.netloc contains the domain name
        if parsed_url.scheme and parsed_url.netloc.lower() == "example.com":
            return f"Redirecting to {url}"
        else:
            return "404 Not Found"
    except (ValueError, AttributeError):
        # Catch potential parsing errors for malformed inputs
        return "404 Not Found"

if __name__ == '__main__':
    test_urls = [
        "http://example.com/home",
        "https://example.com/login?user=1",
        "http://www.google.com",
        "https://sub.example.com",
        "not-a-valid-url"
    ]

    print("--- Running 5 Test Cases ---")
    for url in test_urls:
        print(f"Input: {url}")
        print(f"Output: {redirect_url(url)}")
        print("--------------------")