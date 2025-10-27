import re

# The regular expression is compiled once when the module is loaded.
# This regex validates that the URL is on the example.com domain.
ALLOWED_URL_PATTERN = re.compile(r"^https?://(www\.)?example\.com/.*$")

def get_redirect_url(target_url, default_url):
    """
    Determines the redirect URL based on a whitelist pattern.
    If the target URL matches the pre-compiled pattern, it is returned.
    Otherwise, a default URL is returned.

    :param target_url: The URL to validate.
    :param default_url: The fallback URL if validation fails.
    :return: The validated target_url or the default_url.
    """
    if not target_url:
        return default_url

    # If the target URL matches the allowed pattern, it is used.
    if ALLOWED_URL_PATTERN.fullmatch(target_url):
        return target_url
    else:
        # Otherwise, the default URL is used.
        return default_url

def main():
    """Main function with test cases."""
    default_url = "https://example.com/default"

    # Test Cases
    test_urls = [
        "https://example.com/some/path",  # Case 1: Valid HTTPS URL
        "http://www.example.com/another/page.html",  # Case 2: Valid HTTP URL with www
        "https://evil.com/some/path",  # Case 3: Invalid domain
        "https://example.com.evil.com/path",  # Case 4: Invalid domain (tricky)
        "not a url"  # Case 5: Invalid format
    ]

    print("Running Python Test Cases:")
    for i, target in enumerate(test_urls, 1):
        redirect = get_redirect_url(target, default_url)
        print(f"Test Case {i}:")
        print(f"  Target:   {target}")
        print(f"  Redirect: {redirect}\n")

if __name__ == "__main__":
    main()