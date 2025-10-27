import re

# The regular expression is compiled once when the module is loaded.
URL_PATTERN = re.compile(r"^https?://(www\.)?example\.com/.*$")
DEFAULT_URL = "https://default-redirect.com"

def get_redirect_url(target_url):
    """
    Determines the redirect URL based on a pattern match.

    Args:
        target_url: The URL to check.

    Returns:
        The target_url if it matches the pattern, otherwise the default URL.
    """
    if target_url and URL_PATTERN.match(target_url):
        # If the target URL matches, it is used as the redirect target.
        return target_url
    else:
        # If the target URL does not match, a default URL is used.
        return DEFAULT_URL

def main():
    """Main function with test cases."""
    test_urls = [
        "https://www.example.com/path/to/resource", # Should match
        "http://example.com/another-page",          # Should match
        "https://www.google.com",                   # Should not match
        "https://subdomain.example.com/page",       # Should not match
        "ftp://example.com/file"                    # Should not match
    ]

    print("Running Python Test Cases:")
    for url in test_urls:
        redirect_url = get_redirect_url(url)
        print(f"Input: {url} -> Redirect: {redirect_url}")

if __name__ == "__main__":
    main()