from typing import Dict, Optional

# A pre-approved whitelist of pages and their corresponding URLs.
URL_MAP: Dict[str, str] = {
    "home": "https://example.com/home",
    "profile": "https://example.com/user/profile",
    "settings": "https://example.com/user/settings",
    "login": "https://example.com/auth/login",
}
DEFAULT_URL: str = "https://example.com/404"

def get_redirect_url(page_key: Optional[str]) -> str:
    """
    Returns a redirect URL based on a predefined safe list.
    This prevents open redirect vulnerabilities by never using the input
    to construct the URL.

    Args:
        page_key: A string key representing the desired page.

    Returns:
        A hardcoded, safe URL string.
    """
    if not page_key:
        return DEFAULT_URL

    # Safely get the URL from the map; if not found, return the default.
    return URL_MAP.get(page_key, DEFAULT_URL)

def main():
    """Main function with test cases."""
    test_cases = [
        "home",
        "settings",
        "dashboard",  # Invalid key
        "",           # Empty key
        "//malicious-site.com",  # Malicious input attempt
        None          # Null input
    ]

    print("Running test cases for get_redirect_url:")
    for i, test_input in enumerate(test_cases):
        output_url = get_redirect_url(test_input)
        print(f'Test {i+1}: Input: "{test_input}" -> Redirect URL: {output_url}')

if __name__ == "__main__":
    main()