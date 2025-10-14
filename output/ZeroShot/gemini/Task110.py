import re
from urllib.parse import urlparse

# Set a reasonable length limit for security to prevent denial-of-service attacks.
MAX_URL_LENGTH = 2048

def validate_url(url_string):
    """
    Validates a URL using a combination of Python's urlparse and a regular expression.
    This provides a two-step validation: first for overall structure, then for
    the host part specifically, which urlparse is lenient about.

    :param url_string: The URL string to validate.
    :return: True if the URL is valid, False otherwise.
    """
    # 1. Check for null and unreasonable length.
    if not url_string or len(url_string) > MAX_URL_LENGTH:
        return False

    try:
        # 2. Use urlparse for initial structural validation.
        result = urlparse(url_string)
        # It must have a scheme (e.g., http) and a network location (e.g., www.google.com).
        if not all([result.scheme in ['http', 'https', 'ftp'], result.netloc]):
            return False

        # 3. urlparse can be too lenient on the hostname. Use a regex for stricter validation
        # of the hostname/IP address part, based on RFCs.
        # This regex checks for valid hostnames (prevents leading/trailing hyphens) and IPv4s.
        hostname = result.hostname
        if not hostname:
            return False

        # Regex for valid domain name labels and IPv4 addresses.
        # This is a practical, not exhaustive, regex.
        host_regex = re.compile(
            r'^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,63}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', re.IGNORECASE)  # or ip

        return re.fullmatch(host_regex, hostname) is not None

    except (ValueError, AttributeError):
        # ValueError can be raised on some invalid IPv6 addresses
        return False


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://example.com/path?name=value#fragment",
        "ftp://127.0.0.1:21/resource",
        "www.google.com",  # Invalid: no scheme
        "http://invalid-.com",  # Invalid: domain label ends with hyphen
        "garbage"  # Invalid: not a URL
    ]

    print("Python URL Validation:")
    for url in test_urls:
        print(f'URL: "{url}" -> {"Valid" if validate_url(url) else "Invalid"}')