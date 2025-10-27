from urllib.parse import urlparse

def redirect_url(url):
    """
    Checks if a URL's host is 'example.com' and returns a redirect message.
    Otherwise, returns a 404 error message. This implementation is secure
    against open redirect vulnerabilities by strictly checking the hostname.

    :param url: The URL string to validate.
    :return: A string indicating redirection or a 404 error.
    """
    if not isinstance(url, str):
        return "404 Not Found"
        
    try:
        parsed_url = urlparse(url)
        # Using .hostname is safer than .netloc as it extracts only the host part,
        # ignoring port numbers or user info.
        hostname = parsed_url.hostname
        
        # The hostname must exist and be exactly 'example.com' (case-insensitive).
        if hostname and hostname.lower() == 'example.com':
            # In a real web application, this would trigger an HTTP 301/302 response.
            # For this example, we return a success message with the original URL.
            return f"Redirecting to: {url}"
        else:
            return "404 Not Found"
    except Exception:
        # Catch any other potential parsing errors, although urlparse is very robust.
        return "404 Not Found"

def main():
    test_urls = [
        "https://example.com/path/to/resource",
        "http://www.google.com",
        "https://evil-example.com",
        "https://example.com.hacker.com/login",
        "ftp://example.com:21/files"
    ]

    print("Running Python Test Cases:")
    for url in test_urls:
        print(f"Input: {url}")
        print(f"Output: {redirect_url(url)}")
        print("--------------------")

if __name__ == "__main__":
    main()