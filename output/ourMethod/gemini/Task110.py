import re
from typing import Optional

def is_valid_url(url_string: Optional[str]) -> bool:
    """
    Validates if a given string is a well-formed URL using a regular expression.

    Args:
        url_string: The string to validate.

    Returns:
        True if the string is a valid URL, False otherwise.
    """
    if not isinstance(url_string, str) or not url_string.strip():
        return False

    # A comprehensive regex for URL validation.
    # It checks for a scheme, domain/IP, optional port, and optional path.
    # This regex is designed to be safe from ReDoS attacks.
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S*)$', re.IGNORECASE)

    return re.match(regex, url_string) is not None

def main():
    """Main function with test cases."""
    test_urls = [
        "https://www.google.com",
        "http://example.com/path?query=1",
        "ftp://ftp.is.co.za/rfc/rfc1808.txt",
        "www.invalid.com",
        "https://",
        "http://exa mple.com"
    ]

    print("Running URL validation tests:")
    for url in test_urls:
        print(f"URL: \"{url}\" -> Valid: {is_valid_url(url)}")

if __name__ == "__main__":
    main()