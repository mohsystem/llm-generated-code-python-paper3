class PermissionManager:
    """Manages user permissions and privileges."""

    def __init__(self):
        # Using dictionaries to store roles and user assignments
        # roles: {"role_name": {"permission1", "permission2"}}
        # users: {"user_name": "role_name"}
        self._roles = {}
        self._users = {}

    def add_role(self, role_name, permissions):
        """Adds a new role with a set of permissions."""
        if isinstance(role_name, str) and role_name and isinstance(permissions, set):
            self._roles[role_name] = permissions.copy()

    def assign_role_to_user(self, user_name, role_name):
        """Assigns an existing role to a user."""
        if isinstance(user_name, str) and user_name and role_name in self._roles:
            self._users[user_name] = role_name

    def check_permission(self, user_name, permission):
        """
        Checks if a user has a specific permission.

        Args:
            user_name (str): The name of the user.
            permission (str): The permission to check.

        Returns:
            bool: True if the user has the permission, False otherwise.
        """
        if not isinstance(user_name, str) or not isinstance(permission, str):
            return False

        # Safely get the user's role
        role_name = self._users.get(user_name)
        if not role_name:
            return False

        # Safely get the permissions for that role
        role_permissions = self._roles.get(role_name)
        if not role_permissions:
            return False

        # Check if the permission is in the role's permission set
        return permission in role_permissions

def main():
    """Main function to run test cases."""
    manager = PermissionManager()

    # 1. Define permissions and roles
    permissions = {
        "ADMIN": {"READ", "WRITE", "DELETE", "EXECUTE"},
        "EDITOR": {"READ", "WRITE"},
        "VIEWER": {"READ"}
    }
    
    for role, perms in permissions.items():
        manager.add_role(role, perms)

    # 2. Create users and assign roles
    manager.assign_role_to_user("alice", "ADMIN")
    manager.assign_role_to_user("bob", "EDITOR")
    manager.assign_role_to_user("charlie", "VIEWER")

    print("Running test cases...\n")

    # Test Case 1: Admin user checking an admin-only permission
    print("Test 1: Does alice (ADMIN) have 'DELETE' permission?")
    print(f"Result: {manager.check_permission('alice', 'DELETE')}") # Expected: True

    # Test Case 2: Editor user checking an editor permission
    print("\nTest 2: Does bob (EDITOR) have 'WRITE' permission?")
    print(f"Result: {manager.check_permission('bob', 'WRITE')}") # Expected: True

    # Test Case 3: Editor user checking an admin-only permission
    print("\nTest 3: Does bob (EDITOR) have 'DELETE' permission?")
    print(f"Result: {manager.check_permission('bob', 'DELETE')}") # Expected: False

    # Test Case 4: Viewer user checking a read-only permission
    print("\nTest 4: Does charlie (VIEWER) have 'READ' permission?")
    print(f"Result: {manager.check_permission('charlie', 'READ')}") # Expected: True

    # Test Case 5: Non-existent user checking any permission
    print("\nTest 5: Does david (non-existent) have 'READ' permission?")
    print(f"Result: {manager.check_permission('david', 'READ')}") # Expected: False

if __name__ == "__main__":
    main()