# A whitelist of allowed resources and their internal paths.
# This prevents path traversal as user input is only used as a key.
ALLOWED_RESOURCES = {
    "profile": "data/user_profile.dat",
    "settings": "config/app_settings.json",
    "dashboard": "pages/dashboard.html"
}

def access_resource(resource_key: str) -> str:
    """
    Securely accesses a resource based on a predefined whitelist.

    :param resource_key: The user-provided key for the resource.
    :return: A string indicating the result of the access attempt.
    """
    # Input validation: Check for None or empty/whitespace-only input.
    if not resource_key or not resource_key.strip():
        return "Error: Resource key cannot be empty."

    # Securely check if the key exists in our whitelist dictionary.
    # The .get() method returns None if the key is not found.
    resource_path = ALLOWED_RESOURCES.get(resource_key)

    if resource_path:
        # In a real application, you would now use 'resource_path' to read the file.
        # For this example, we just simulate the access.
        return f"Success: Accessing resource at {resource_path}"
    else:
        # Generic error message to avoid leaking information about valid resources.
        return "Error: Resource not found or access denied."

if __name__ == "__main__":
    print("Python Test Cases:")
    
    test_cases = [
        "profile",          # Valid case 1
        "settings",         # Valid case 2
        "logs",             # Invalid case
        "../etc/passwd",    # Path traversal attempt
        ""                  # Empty input
    ]

    for test in test_cases:
        print(f'Input: "{test}" -> Output: {access_resource(test)}')