def get_resource(resource_name: str) -> str:
    """
    Accesses a resource based on the provided resource name.
    
    Args:
        resource_name: The name of the resource to access.
        
    Returns:
        The resource content if found, otherwise an error message.
    """
    resources = {
        "profile": "User Profile Data: { 'user': 'John Doe', 'email': 'john.doe@example.com' }",
        "settings": "Account Settings Page: [ 'Theme: Dark', 'Language: English' ]",
        "dashboard": "Main Dashboard View: Widgets and Stats",
        "logs": "System Activity Logs: [ 'INFO: User login', 'WARN: Low disk space' ]"
    }
    
    # Use .get() for safe access, providing a default value if the key is not found
    content = resources.get(resource_name.lower())
    
    if content:
        return f"Accessing {resource_name}: {content}"
    else:
        return f"Access Denied: Resource '{resource_name}' not found."

def main():
    """ Main function with test cases """
    test_cases = ["profile", "dashboard", "admin", "settings", "data"]
    
    print("--- Python Test Cases ---")
    for test_case in test_cases:
        print(f"Input: {test_case}")
        result = get_resource(test_case)
        print(f"Output: {result}\n")

if __name__ == "__main__":
    main()