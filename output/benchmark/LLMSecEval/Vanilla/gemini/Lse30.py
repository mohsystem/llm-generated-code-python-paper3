import re

def get_redirect_url(target):
    """
    Determines the redirect URL based on a regex match.
    The regex matches a string that starts with one or more alphanumeric characters or hyphens,
    followed by a period.
    
    Args:
        target: The target query parameter string.
    
    Returns:
        A string indicating redirection to the target if it matches, or to the root ("/") otherwise.
    """
    # Regex: starts with one or more alphanumeric/hyphen chars, followed by a period.
    regex = r"^[a-zA-Z0-9-]+\..*"
    if target and re.match(regex, target):
        return f"Redirecting to: {target}"
    else:
        return "Redirecting to: /"

if __name__ == "__main__":
    test_cases = [
        "example.com",
        "sub-domain.example.org/path?query=1",
        "123-valid.net",
        ".invalid-start.com",
        "/local/path/only"
    ]
    
    print("Python Test Cases:")
    for test_case in test_cases:
        result = get_redirect_url(test_case)
        print(f'Input: "{test_case}" -> Output: {result}')