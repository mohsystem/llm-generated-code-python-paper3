import re
import sys

# The regular expression is compiled once when the module is loaded.
# It whitelists URLs from a specific, safe domain.
SAFE_URL_PATTERN = re.compile(r"^https://safe\.example\.com/([a-zA-Z0-9/\-]+)$")
DEFAULT_URL = "https://example.com/default"

def get_redirect_url(target_url: str) -> str:
    """
    Determines the redirect URL based on a whitelist pattern.
    If the target URL matches the pre-compiled regular expression, it is returned.
    Otherwise, a default URL is returned.

    Args:
        target_url: The URL to validate for redirection.
    
    Returns:
        The target_url if it's valid, otherwise the default URL.
    """
    if target_url is None:
        return DEFAULT_URL
    
    # The regular expression is used to match the target URL.
    # fullmatch() ensures the entire string matches the pattern.
    if SAFE_URL_PATTERN.fullmatch(target_url):
        # If the target URL matches, it is used as the redirect target.
        # The regex is not used to construct the URL, preventing manipulation.
        return target_url
    else:
        # If the target URL does not match, a default URL is used.
        return DEFAULT_URL

def main():
    """Main function with test cases."""
    test_urls = [
        # Test Case 1: Valid URL
        "https://safe.example.com/valid-path",
        # Test Case 2: Valid URL with sub-path
        "https://safe.example.com/user/profile-123",
        # Test Case 3: Invalid domain
        "https://unsafe.example.com/path",
        # Test Case 4: Invalid characters (query parameters are not allowed by the regex)
        "https://safe.example.com/path?query=malicious",
        # Test Case 5: URL trying to bypass with different protocol or domain format
        "http://safe.example.com/path"
    ]

    print("Python Test Cases:")
    for url in test_urls:
        print(f"Input:  {url}")
        print(f"Output: {get_redirect_url(url)}")
        print("--------------------")

if __name__ == "__main__":
    main()