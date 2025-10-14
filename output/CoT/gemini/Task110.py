import re

def is_valid_url(url: str) -> bool:
    """
    Validates a URL using a regular expression.
    This regex checks for http, https, or ftp schemes, a valid domain name,
    and an optional path.

    :param url: The string to validate.
    :return: True if the URL is valid, False otherwise.
    """
    # Handle non-string, None, or empty input
    if not isinstance(url, str) or not url.strip():
        return False

    # Regex for a standard URL (http, https, ftp)
    # ^(https?|ftp)://    - Scheme (http, https, ftp)
    # [a-zA-Z0-9.-]+      - Domain name characters
    # \.[a-zA-Z]{2,}      - Top-level domain (at least 2 letters)
    # (?:/[^\s]*)?$       - Optional path (any non-whitespace characters)
    url_regex = re.compile(r"^(https?|ftp)://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?$")

    # Use re.fullmatch to ensure the entire string matches the pattern
    return bool(re.fullmatch(url_regex, url))

if __name__ == "__main__":
    test_urls = [
        "https://www.example.com",
        "http://example.co.uk/path/to/page?query=123",
        "ftp://ftp.example.com/resource",
        "htp://invalid-scheme.com",  # Invalid scheme
        "https://.invalid-domain.com", # Invalid domain
        "https://domain-without-tld",  # Invalid TLD
        "Just a string",  # Not a URL
        ""  # Empty string
    ]

    print("Running URL validation test cases in Python:")
    for url in test_urls:
        print(f'URL: "{url}" -> {"Valid" if is_valid_url(url) else "Invalid"}')