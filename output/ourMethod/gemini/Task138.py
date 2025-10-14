import sys
from typing import Set, Dict, Optional

class PermissionManager:
    def __init__(self):
        self.roles_to_permissions: Dict[str, Set[str]] = {}
        self.users_to_roles: Dict[str, Set[str]] = {}

    def add_user(self, username: Optional[str]) -> bool:
        if not username or not username.strip():
            print("Error: Username cannot be empty.", file=sys.stderr)
            return False
        if username in self.users_to_roles:
            print(f"Error: User '{username}' already exists.", file=sys.stderr)
            return False
        self.users_to_roles[username] = set()
        return True

    def add_role(self, role_name: Optional[str], permissions: Optional[Set[str]]) -> bool:
        if not role_name or not role_name.strip():
            print("Error: Role name cannot be empty.", file=sys.stderr)
            return False
        if not permissions:
            print("Error: Permissions set cannot be empty.", file=sys.stderr)
            return False
        # Defensive copy
        self.roles_to_permissions[role_name] = permissions.copy()
        return True

    def assign_role_to_user(self, username: Optional[str], role_name: Optional[str]) -> bool:
        if not username or username not in self.users_to_roles:
            print(f"Error: User '{(username or 'None')}' not found.", file=sys.stderr)
            return False
        if not role_name or role_name not in self.roles_to_permissions:
            print(f"Error: Role '{(role_name or 'None')}' not found.", file=sys.stderr)
            return False
        self.users_to_roles[username].add(role_name)
        return True

    def check_permission(self, username: Optional[str], permission: Optional[str]) -> bool:
        if not username or username not in self.users_to_roles:
            # Fail closed
            return False
        if not permission or not permission.strip():
            return False

        user_roles = self.users_to_roles.get(username, set())
        for role_name in user_roles:
            permissions = self.roles_to_permissions.get(role_name, set())
            if permission in permissions:
                return True
        return False

def main():
    pm = PermissionManager()

    print("--- Test Case 1: Basic Setup and Permission Check ---")
    pm.add_role("admin", {"read", "write", "delete"})
    pm.add_role("editor", {"read", "write"})
    pm.add_role("viewer", {"read"})
    pm.add_user("alice")
    pm.add_user("bob")
    pm.assign_role_to_user("alice", "admin")
    pm.assign_role_to_user("bob", "editor")

    print(f"Does alice have 'delete' permission? {pm.check_permission('alice', 'delete')}")
    print(f"Does bob have 'delete' permission? {pm.check_permission('bob', 'delete')}")
    print(f"Does bob have 'write' permission? {pm.check_permission('bob', 'write')}")
    print()

    print("--- Test Case 2: User with multiple roles ---")
    pm.add_user("charlie")
    pm.assign_role_to_user("charlie", "viewer")
    pm.assign_role_to_user("charlie", "editor")
    print(f"Does charlie have 'write' permission? {pm.check_permission('charlie', 'write')}")
    print(f"Does charlie have 'read' permission? {pm.check_permission('charlie', 'read')}")
    print()

    print("--- Test Case 3: Non-existent user, role, or permission ---")
    print(f"Does non_existent_user have 'read' permission? {pm.check_permission('non_existent_user', 'read')}")
    print(f"Does alice have 'execute' permission? {pm.check_permission('alice', 'execute')}")
    print(f"Assigning non-existent role: {pm.assign_role_to_user('alice', 'super_admin')}")
    print()

    print("--- Test Case 4: User with no roles ---")
    pm.add_user("dave")
    print(f"Does dave have 'read' permission? {pm.check_permission('dave', 'read')}")
    print()

    print("--- Test Case 5: Invalid inputs ---")
    print(f"Adding user with None name: {pm.add_user(None)}")
    print(f"Adding user with empty name: {pm.add_user('  ')}")
    print(f"Checking None permission for alice: {pm.check_permission('alice', None)}")
    print()


if __name__ == "__main__":
    main()