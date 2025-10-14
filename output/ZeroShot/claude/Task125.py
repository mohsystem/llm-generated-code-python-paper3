import re

class Task125:
    ALLOWED_RESOURCES = {
        "document1.txt", "document2.txt", "image1.jpg", "image2.jpg", "data.csv"
    }

    VALID_RESOURCE_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

    @staticmethod
    def access_resource(username, resource_name):
        """Securely access resources based on user input with validation and whitelist checking."""
        # Input validation
        if not username or not username.strip():
            return "Error: Invalid username"

        if not resource_name or not resource_name.strip():
            return "Error: Invalid resource name"

        # Sanitize input - remove whitespace
        resource_name = resource_name.strip()

        # Validate resource name format (prevent path traversal)
        if not Task125.VALID_RESOURCE_PATTERN.match(resource_name):
            return "Error: Invalid resource name format"

        # Check for path traversal attempts
        if ".." in resource_name or "/" in resource_name or "\\" in resource_name:
            return "Error: Path traversal attempt detected"

        # Check if resource is in whitelist
        if resource_name not in Task125.ALLOWED_RESOURCES:
            return "Error: Access denied - resource not found or unauthorized"

        # Simulate resource access
        return f"Success: User '{username}' accessed resource '{resource_name}'"


def main():
    print("=== Resource Access Control System ===\n")

    # Test case 1: Valid access
    print("Test 1 - Valid access:")
    print(Task125.access_resource("john_doe", "document1.txt"))
    print()

    # Test case 2: Valid access to different resource
    print("Test 2 - Valid access to image:")
    print(Task125.access_resource("jane_smith", "image1.jpg"))
    print()

    # Test case 3: Attempt to access non-existent resource
    print("Test 3 - Non-existent resource:")
    print(Task125.access_resource("user1", "secret.txt"))
    print()

    # Test case 4: Path traversal attempt
    print("Test 4 - Path traversal attempt:")
    print(Task125.access_resource("attacker", "../../../etc/passwd"))
    print()

    # Test case 5: Invalid input
    print("Test 5 - Invalid input:")
    print(Task125.access_resource("", "document1.txt"))
    print(Task125.access_resource("user2", ""))
    print()


if __name__ == "__main__":
    main()
