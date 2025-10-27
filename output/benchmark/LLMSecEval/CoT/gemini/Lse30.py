import re

def get_redirect_url(target: str) -> str:
    """
    Determines the redirect URL based on a target parameter.
    The regular expression matches a string that starts with one or more
    alphanumeric characters or hyphens, followed by a period.
    This is a security measure to prevent open redirect vulnerabilities.

    :param target: The target query parameter.
    :return: The target if it matches the safe pattern, otherwise "/" (the root of the site).
    """
    # The regex ensures the target starts like a domain name (e.g., "example.com")
    # and is not a scheme-relative URL (e.g., "//evil.com") or an absolute path (e.g., "/login").
    safe_redirect_pattern = r"^[a-zA-Z0-9-]+\..*"

    # Check for None or empty input, which is considered invalid.
    if not target or not target.strip():
        return "/"

    # re.match checks for a match only at the beginning of the string.
    # If the target matches the safe pattern, it's considered safe for redirection.
    if re.match(safe_redirect_pattern, target):
        return target

    # Otherwise, redirect to the root to prevent a potential open redirect attack.
    return "/"

if __name__ == "__main__":
    test_cases = [
        "example.com/home",        # Valid: Standard domain with path
        "sub-domain.net?query=1",  # Valid: Subdomain with query string
        "/local/path",             # Invalid: Does not start with a domain-like pattern
        "justaword",               # Invalid: No period
        "@bad.com/path"            # Invalid: Starts with a disallowed character
    ]

    print("Running Python Test Cases:")
    for test_case in test_cases:
        result = get_redirect_url(test_case)
        print(f'Input: "{test_case}", Redirect To: "{result}"')