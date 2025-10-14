# A secure, allowlisted dictionary of page keys to their full URLs.
ALLOWED_REDIRECTS = {
    "home": "https://example.com/home",
    "about": "https://example.com/about",
    "contact": "https://example.com/contact-us",
    "products": "https://example.com/products"
}
DEFAULT_URL = "https://example.com/error"

def get_redirect_url(page_key: str) -> str:
    """
    Securely gets a redirect URL based on a predefined allowlist.
    Prevents open redirect vulnerabilities by looking up the key in a safe map.

    Args:
        page_key: The user-provided key for the desired page.

    Returns:
        The corresponding URL from the allowlist, or a default URL if the key is not found.
    """
    # .get() method is safe: it returns None if the key is not found.
    return ALLOWED_REDIRECTS.get(page_key, DEFAULT_URL)

if __name__ == "__main__":
    test_cases = [
        "home",           # Test case 1: Valid input
        "contact",        # Test case 2: Another valid input
        "dashboard",      # Test case 3: Invalid input
        "//evil.com",     # Test case 4: Malicious input attempt
        ""                # Test case 5: Empty input
    ]

    print("Running Python Test Cases:")
    for test_case in test_cases:
        redirect_url = get_redirect_url(test_case)
        print(f"Input: '{test_case}' -> Redirecting to: {redirect_url}")