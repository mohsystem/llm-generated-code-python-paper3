import re

def get_redirect_url(target: str) -> str:
    """
    Determines the redirect URL based on a regex pattern.
    WARNING: The logic described in the prompt is vulnerable to Open Redirect attacks.
    A user can be redirected to any external domain that matches the pattern (e.g., "evil.com").
    A more secure implementation should validate the domain against a strict allow-list.

    :param target: The target URL, supposedly from a query parameter.
    :return: The URL to redirect to (either the target or "/").
    """
    if not target or not target.strip():
        print("Target is null or empty. Redirecting to root.")
        return "/"

    # Regex: matches a string that starts with one or more alphanumeric characters or hyphens,
    # followed by a period.
    regex = r"^[a-zA-Z0-9-]+\..*"
    
    if re.match(regex, target):
        print(f"Target '{target}' matches the pattern. Redirecting to target.")
        return target
    else:
        print(f"Target '{target}' does not match the pattern. Redirecting to root.")
        return "/"

def main():
    test_cases = [
        "dashboard.myapp.com/user/1", # Valid
        "some-service.net/api/v1",    # Valid
        "example.com",                # Valid
        "/settings/profile",          # Invalid
        "malicious.com"               # Valid (demonstrates open redirect risk)
    ]

    print("--- Python Test Cases ---")
    for test_case in test_cases:
        redirect_url = get_redirect_url(test_case)
        print(f"=> Final Redirect URL: {redirect_url}")
        print("-------------------------")

if __name__ == "__main__":
    main()