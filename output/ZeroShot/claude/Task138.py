
import hashlib
from typing import Set, Dict, Optional

class User:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password_hash = self._hash_password(password)
        self.roles: Set[str] = set()
        self.permissions: Set[str] = set()
    
    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password: str) -> bool:
        return self.password_hash == self._hash_password(password)
    
    def add_role(self, role: str):
        self.roles.add(role)
    
    def remove_role(self, role: str):
        self.roles.discard(role)
    
    def add_permission(self, permission: str):
        self.permissions.add(permission)
    
    def remove_permission(self, permission: str):
        self.permissions.discard(permission)
    
    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions
    
    def has_role(self, role: str) -> bool:
        return role in self.roles
    
    def get_roles(self) -> Set[str]:
        return self.roles.copy()
    
    def get_permissions(self) -> Set[str]:
        return self.permissions.copy()


class PermissionManager:
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.role_permissions: Dict[str, Set[str]] = {}
        self._initialize_default_roles()
    
    def _initialize_default_roles(self):
        self.role_permissions['ADMIN'] = {
            'CREATE_USER', 'DELETE_USER', 'MODIFY_USER', 'READ_USER',
            'CREATE_ROLE', 'DELETE_ROLE', 'ASSIGN_ROLE'
        }
        self.role_permissions['MANAGER'] = {
            'READ_USER', 'MODIFY_USER', 'ASSIGN_ROLE'
        }
        self.role_permissions['USER'] = {
            'READ_USER'
        }
    
    def create_user(self, username: str, password: str) -> bool:
        if username in self.users:
            return False
        self.users[username] = User(username, password)
        return True
    
    def authenticate_user(self, username: str, password: str) -> bool:
        user = self.users.get(username)
        if user is None:
            return False
        return user.verify_password(password)
    
    def assign_role(self, username: str, role: str) -> bool:
        user = self.users.get(username)
        if user is None or role not in self.role_permissions:
            return False
        user.add_role(role)
        permissions = self.role_permissions[role]
        for permission in permissions:
            user.add_permission(permission)
        return True
    
    def revoke_role(self, username: str, role: str) -> bool:
        user = self.users.get(username)
        if user is None:
            return False
        user.remove_role(role)
        self._recalculate_permissions(username)
        return True
    
    def _recalculate_permissions(self, username: str):
        user = self.users.get(username)
        if user is None:
            return
        
        all_permissions = set()
        for role in user.get_roles():
            role_perms = self.role_permissions.get(role)
            if role_perms:
                all_permissions.update(role_perms)
        
        user.permissions.clear()
        user.permissions.update(all_permissions)
    
    def grant_permission(self, username: str, permission: str) -> bool:
        user = self.users.get(username)
        if user is None:
            return False
        user.add_permission(permission)
        return True
    
    def revoke_permission(self, username: str, permission: str) -> bool:
        user = self.users.get(username)
        if user is None:
            return False
        user.remove_permission(permission)
        return True
    
    def check_permission(self, username: str, permission: str) -> bool:
        user = self.users.get(username)
        if user is None:
            return False
        return user.has_permission(permission)
    
    def get_user_permissions(self, username: str) -> Set[str]:
        user = self.users.get(username)
        if user is None:
            return set()
        return user.get_permissions()
    
    def get_user_roles(self, username: str) -> Set[str]:
        user = self.users.get(username)
        if user is None:
            return set()
        return user.get_roles()


def main():
    pm = PermissionManager()
    
    # Test Case 1: Create users and authenticate
    print("Test Case 1: User Creation and Authentication")
    pm.create_user("alice", "password123")
    pm.create_user("bob", "securepass")
    print(f"Alice authentication: {pm.authenticate_user('alice', 'password123')}")
    print(f"Bob wrong password: {pm.authenticate_user('bob', 'wrongpass')}")
    print()
    
    # Test Case 2: Assign roles to users
    print("Test Case 2: Role Assignment")
    pm.assign_role("alice", "ADMIN")
    pm.assign_role("bob", "USER")
    print(f"Alice roles: {pm.get_user_roles('alice')}")
    print(f"Bob roles: {pm.get_user_roles('bob')}")
    print()
    
    # Test Case 3: Check permissions based on roles
    print("Test Case 3: Permission Checking")
    print(f"Alice has CREATE_USER: {pm.check_permission('alice', 'CREATE_USER')}")
    print(f"Bob has CREATE_USER: {pm.check_permission('bob', 'CREATE_USER')}")
    print(f"Bob has READ_USER: {pm.check_permission('bob', 'READ_USER')}")
    print()
    
    # Test Case 4: Grant and revoke specific permissions
    print("Test Case 4: Grant and Revoke Permissions")
    pm.grant_permission("bob", "MODIFY_USER")
    print(f"Bob permissions after grant: {pm.get_user_permissions('bob')}")
    pm.revoke_permission("bob", "MODIFY_USER")
    print(f"Bob permissions after revoke: {pm.get_user_permissions('bob')}")
    print()
    
    # Test Case 5: Multiple roles and permission inheritance
    print("Test Case 5: Multiple Roles")
    pm.create_user("charlie", "charlie123")
    pm.assign_role("charlie", "USER")
    pm.assign_role("charlie", "MANAGER")
    print(f"Charlie roles: {pm.get_user_roles('charlie')}")
    print(f"Charlie permissions: {pm.get_user_permissions('charlie')}")
    pm.revoke_role("charlie", "MANAGER")
    print(f"Charlie permissions after revoking MANAGER: {pm.get_user_permissions('charlie')}")


if __name__ == "__main__":
    main()
