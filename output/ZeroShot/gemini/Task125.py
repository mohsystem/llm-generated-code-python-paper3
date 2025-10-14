# Define a whitelist of available resources
RESOURCES = {
    "1": "Public Document",
    "2": "User Profile",
    "3": "Admin Panel",
    "4": "System Logs"
}

# Define role-based access control permissions
ROLE_PERMISSIONS = {
    "GUEST": {"1"},
    "USER": {"1", "2"},
    "ADMIN": {"1", "2", "3", "4"}
}

def access_resource(resource_id, user_role):
    """
    Securely accesses a resource based on a user's role and requested resource ID.

    Args:
        resource_id (str): The identifier for the resource to be accessed.
        user_role (str): The role of the user requesting access.

    Returns:
        str: A string indicating the result of the access attempt.
    """
    # 1. Validate user role
    if user_role not in ROLE_PERMISSIONS:
        return "Error: Invalid user role provided."

    # 2. Validate resource ID against the whitelist
    if resource_id not in RESOURCES:
        return "Access Denied: Resource not found."

    # 3. Check if the user's role has permission for the resource
    if resource_id in ROLE_PERMISSIONS.get(user_role, set()):
        resource_name = RESOURCES[resource_id]
        return f"Access Granted. Now accessing: {resource_name}"
    else:
        return "Access Denied: You do not have permission to access this resource."

def main():
    """ Main function with test cases """
    print("Running test cases...")
    
    # Test Case 1: Guest accessing a public resource (should be granted)
    print(f"Test 1 (GUEST, Resource '1'): {access_resource('1', 'GUEST')}")

    # Test Case 2: Guest trying to access an admin resource (should be denied)
    print(f"Test 2 (GUEST, Resource '3'): {access_resource('3', 'GUEST')}")

    # Test Case 3: Admin accessing an admin resource (should be granted)
    print(f"Test 3 (ADMIN, Resource '3'): {access_resource('3', 'ADMIN')}")

    # Test Case 4: User trying to access a non-existent resource (should be denied)
    print(f"Test 4 (USER, Resource '99'): {access_resource('99', 'USER')}")

    # Test Case 5: User accessing their profile (should be granted)
    print(f"Test 5 (USER, Resource '2'): {access_resource('2', 'USER')}")

if __name__ == "__main__":
    main()