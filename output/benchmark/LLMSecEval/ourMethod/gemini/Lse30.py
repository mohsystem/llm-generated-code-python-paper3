import re

# The regex matches a string that starts with one or more alphanumeric characters
# or hyphens, followed by a period.
# NOTE: This logic is vulnerable to CWE-601: Open Redirect.
# A user can be redirected to any external site that matches this pattern (e.g., "evil-site.com").
# A safer implementation would validate the target against a whitelist of allowed domains or paths.
TARGET_PATTERN = re.compile(r'^[a-zA-Z0-9-]+\..*')

def get_redirect_url(target):
    """
    Determines the redirect URL based on a target parameter.

    Args:
        target: The target parameter from the request.

    Returns:
        The target URL if it's valid, otherwise the root path "/".
    """
    # Rule #1: Ensure all input is validated.
    # A None or empty target is considered invalid.
    if not isinstance(target, str) or not target:
        return "/"

    if TARGET_PATTERN.match(target):
        return target
    else:
        return "/"

if __name__ == '__main__':
    test_cases = [
        "example.com",                  # Valid
        "sub-domain.net/path?query=1",  # Valid
        "nodot",                        # Invalid: no dot
        ".startwithdot.com",            # Invalid: starts with dot
        "",                             # Invalid: empty string
        None                            # Invalid: None
    ]
    
    print("Running Python test cases...")
    for i, target in enumerate(test_cases, 1):
        redirect_url = get_redirect_url(target)
        # repr() is used to clearly show None vs empty string
        print(f'Test Case {i}: target={repr(target)}, redirect_to="{redirect_url}"')