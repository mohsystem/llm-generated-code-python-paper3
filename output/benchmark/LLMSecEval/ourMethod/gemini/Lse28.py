import re
from typing import Optional

# The default URL to use if the target URL does not match the safe pattern.
DEFAULT_URL = "https://default.example.com"

# The regular expression is compiled once when the module is loaded for efficiency.
# The pattern uses `^` and `$` to ensure the entire string matches the whitelist.
SAFE_URL_PATTERN = re.compile(r"^https://safe\.example\.com/.*$")

def get_redirect_url(target_url: Optional[str]) -> str:
    """
    Determines the redirect URL based on a whitelist pattern.

    Args:
        target_url: The URL to check.

    Returns:
        The target_url if it matches the safe pattern, otherwise the default URL.
    """
    # Rule #1: Validate input. Check for None or empty/whitespace-only strings.
    if not target_url or not target_url.strip():
        return DEFAULT_URL

    # If the target URL fully matches the pre-compiled regex, it is considered safe.
    # `fullmatch` is used to ensure the entire string conforms to the pattern.
    if SAFE_URL_PATTERN.fullmatch(target_url):
        return target_url

    # If the target URL does not match, return the default URL.
    return DEFAULT_URL

def main():
    """
    Runs test cases for the get_redirect_url function.
    """
    test_urls = [
        # Test Case 1: Valid URL that should be allowed.
        "https://safe.example.com/user/profile",
        # Test Case 2: URL from an untrusted domain.
        "https://unsafe.example.com/user/profile",
        # Test Case 3: URL with an insecure protocol.
        "http://safe.example.com/user/profile",
        # Test Case 4: Empty input string.
        "",
        # Test Case 5: None input.
        None
    ]

    print("--- Python Test Cases ---")
    for url in test_urls:
        redirect_url = get_redirect_url(url)
        # Displaying None as "None" for clarity in output
        input_str = f'"{url}"' if url is not None else "None"
        print(f"Input:  {input_str}\nOutput: \"{redirect_url}\"\n")

if __name__ == "__main__":
    main()