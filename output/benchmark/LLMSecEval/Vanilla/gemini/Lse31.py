from urllib.parse import urlparse

def redirect_url(url: str) -> str:
    """
    Parses a URL to check if its domain is "example.com".

    :param url: The URL to check.
    :return: "redirected" if the domain is "example.com", otherwise "404 error".
    """
    try:
        # urlparse is used to parse the URL into components.
        parsed_url = urlparse(url)
        # The 'hostname' attribute gives the domain name, ignoring the port.
        domain = parsed_url.hostname
        
        # Check if the domain is exactly "example.com"
        if domain == "example.com":
            return "redirected"
        else:
            return "404 error"
    except Exception:
        # Any parsing error results in a 404.
        return "404 error"

if __name__ == "__main__":
    test_urls = [
        "https://example.com/home",
        "http://www.example.com/test",
        "ftp://google.com/files",
        "https://example.com:8080/path?a=1",
        "not_a_valid_url"
    ]

    print("Python Test Cases:")
    for url in test_urls:
        print(f"URL: {url} -> {redirect_url(url)}")