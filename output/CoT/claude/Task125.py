
import re
from typing import Dict, Optional

class Task125:
    # Define allowed users and their resources
    USER_RESOURCES = {
        'user1': {
            'document1': 'Content of Document 1 for User1',
            'report2': 'Annual Report Data for User1'
        },
        'user2': {
            'file3': 'Private File Content for User2',
            'data4': 'Database Export for User2'
        },
        'admin': {
            'config': 'System Configuration Data',
            'logs': 'System Logs and Monitoring'
        }
    }
    
    VALID_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
    VALID_RESOURCE_PATTERN = re.compile(r'^[a-zA-Z0-9_]{1,50}$')
    
    @staticmethod
    def access_resource(username: Optional[str], resource_name: Optional[str]) -> str:
        """\n        Securely access resources based on user credentials and resource name.\n        \n        Args:\n            username: The username requesting access\n            resource_name: The name of the resource to access\n            \n        Returns:\n            Success message with resource content or error message\n        """
        # Input validation
        if username is None or resource_name is None:
            return "Error: Invalid input - null values not allowed"
        
        # Sanitize and validate username
        username = username.strip()
        if not Task125.VALID_USERNAME_PATTERN.match(username):
            return "Error: Invalid username format"
        
        # Sanitize and validate resource name
        resource_name = resource_name.strip()
        if not Task125.VALID_RESOURCE_PATTERN.match(resource_name):
            return "Error: Invalid resource name format"
        
        # Check if user exists
        if username not in Task125.USER_RESOURCES:
            return "Error: User not found"
        
        # Check if user has access to the resource
        user_resources = Task125.USER_RESOURCES.get(username, {})
        if resource_name not in user_resources:
            return "Error: Access denied - Resource not found or unauthorized"
        
        # Return the resource content
        return f"Success: {user_resources[resource_name]}"


def main():
    print("=== Secure Resource Access Control System ===\\n")
    
    # Test Case 1: Valid access
    print("Test 1 - Valid Access:")
    print(Task125.access_resource("user1", "document1"))
    print()
    
    # Test Case 2: Valid access different user
    print("Test 2 - Valid Access (User2):")
    print(Task125.access_resource("user2", "file3"))
    print()
    
    # Test Case 3: Unauthorized access attempt
    print("Test 3 - Unauthorized Access:")
    print(Task125.access_resource("user1", "file3"))
    print()
    
    # Test Case 4: Path traversal attempt
    print("Test 4 - Path Traversal Attack Attempt:")
    print(Task125.access_resource("user1", "../admin/config"))
    print()
    
    # Test Case 5: Null input handling
    print("Test 5 - Null Input:")
    print(Task125.access_resource(None, "document1"))
    print()


if __name__ == "__main__":
    main()
