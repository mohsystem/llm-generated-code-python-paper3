from typing import Set, Optional

# A predefined set of allowed resources for efficient and safe lookups.
ALLOWED_RESOURCES: Set[str] = {
    "PROFILE", "DASHBOARD", "SETTINGS", "REPORTS"
}

def get_resource_access(resource_id: Optional[str]) -> str:
    """
    Checks if a user has access to a specific resource based on a predefined list.
    This function validates the input and compares it against a safe list of
    allowed resources to prevent unauthorized access.

    Args:
        resource_id: The ID of the resource being requested.

    Returns:
        A string indicating whether access is granted or denied.
    """
    # Rule#6: Ensure all input is validated and sanitized.
    # Check for None or empty/whitespace-only strings.
    if not resource_id or not resource_id.strip():
        return "Access Denied: Invalid resource ID."

    # The check against the predefined set acts as sanitization.
    if resource_id in ALLOWED_RESOURCES:
        # Use safe f-strings for formatting.
        return f"Access Granted to resource: {resource_id}"
    else:
        # Return a generic error to avoid information disclosure.
        return "Access Denied: Resource not found or permission denied."

def main():
    """Main function to run test cases."""
    print("--- Running Test Cases ---")

    # Test Case 1: A valid, allowed resource.
    resource1 = "DASHBOARD"
    print(f"Requesting '{resource1}': {get_resource_access(resource1)}")

    # Test Case 2: Another valid, allowed resource.
    resource2 = "SETTINGS"
    print(f"Requesting '{resource2}': {get_resource_access(resource2)}")

    # Test Case 3: An invalid/unauthorized resource.
    resource3 = "ADMIN_PANEL"
    print(f"Requesting '{resource3}': {get_resource_access(resource3)}")

    # Test Case 4: An empty string input.
    resource4 = ""
    print(f"Requesting 'empty string': {get_resource_access(resource4)}")

    # Test Case 5: A None (null) input.
    resource5 = None
    print(f"Requesting None: {get_resource_access(resource5)}")
    
    print("--- Test Cases Finished ---")

if __name__ == "__main__":
    main()