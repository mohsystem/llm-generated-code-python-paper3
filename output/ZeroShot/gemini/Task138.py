import collections

class PermissionManager:
    """
    Manages user roles and permissions securely.
    - Uses defaultdict for cleaner initialization.
    - Validates inputs to ensure they are non-empty strings.
    - Uses sets for efficient membership testing and to prevent duplicates.
    """
    def __init__(self):
        # Maps role names to a set of permission strings
        self.roles_to_permissions = collections.defaultdict(set)
        # Maps user names to a set of role strings
        self.users_to_roles = collections.defaultdict(set)
        self._existing_users = set()
        self._existing_roles = set()

    def add_role(self, role_name: str) -> bool:
        """Adds a new role to the system."""
        if not isinstance(role_name, str) or not role_name.strip():
            return False
        if role_name in self._existing_roles:
            return False # Role already exists
        self._existing_roles.add(role_name)
        return True

    def add_user(self, username: str) -> bool:
        """Adds a new user to the system."""
        if not isinstance(username, str) or not username.strip():
            return False
        if username in self._existing_users:
            return False # User already exists
        self._existing_users.add(username)
        return True

    def add_permission_to_role(self, role_name: str, permission: str) -> bool:
        """Adds a permission to an existing role."""
        if (not isinstance(role_name, str) or not role_name.strip() or
                not isinstance(permission, str) or not permission.strip()):
            return False
        if role_name not in self._existing_roles:
            return False  # Role does not exist
        self.roles_to_permissions[role_name].add(permission)
        return True

    def assign_role_to_user(self, username: str, role_name: str) -> bool:
        """Assigns an existing role to an existing user."""
        if (not isinstance(username, str) or not username.strip() or
                not isinstance(role_name, str) or not role_name.strip()):
            return False
        if username not in self._existing_users or role_name not in self._existing_roles:
            return False  # User or Role does not exist
        self.users_to_roles[username].add(role_name)
        return True

    def check_permission(self, username: str, permission: str) -> bool:
        """Checks if a user has a specific permission."""
        if (not isinstance(username, str) or not username.strip() or
                not isinstance(permission, str) or not permission.strip()):
            return False
        if username not in self.users_to_roles:
            return False

        user_roles = self.users_to_roles.get(username, set())
        for role in user_roles:
            if permission in self.roles_to_permissions.get(role, set()):
                return True
        return False

def main():
    """Main function to run test cases."""
    manager = PermissionManager()

    # Setup
    manager.add_role("admin")
    manager.add_role("editor")
    manager.add_role("viewer")

    manager.add_permission_to_role("admin", "read")
    manager.add_permission_to_role("admin", "write")
    manager.add_permission_to_role("admin", "delete")
    manager.add_permission_to_role("admin", "manage_users")

    manager.add_permission_to_role("editor", "read")
    manager.add_permission_to_role("editor", "write")

    manager.add_permission_to_role("viewer", "read")

    manager.add_user("alice")
    manager.add_user("bob")
    manager.add_user("charlie")

    manager.assign_role_to_user("alice", "admin")
    manager.assign_role_to_user("bob", "editor")
    manager.assign_role_to_user("charlie", "viewer")

    print("--- Running Test Cases ---")

    # Test Case 1: Admin has delete permission
    print(f"1. Alice has 'delete' permission: {manager.check_permission('alice', 'delete')}")

    # Test Case 2: Editor has write permission
    print(f"2. Bob has 'write' permission: {manager.check_permission('bob', 'write')}")

    # Test Case 3: Editor does NOT have delete permission
    print(f"3. Bob has 'delete' permission: {manager.check_permission('bob', 'delete')}")

    # Test Case 4: Non-existent user
    print(f"4. Dave has 'read' permission: {manager.check_permission('dave', 'read')}")
    
    # Test Case 5: User with multiple roles
    manager.assign_role_to_user("bob", "viewer")  # bob is now editor and viewer
    print(f"5. Bob (now editor & viewer) has 'read' permission: {manager.check_permission('bob', 'read')}")

    print("--- Test Cases Finished ---")

if __name__ == "__main__":
    main()