
import hashlib
import secrets
import base64
import re
from enum import Enum
from typing import Set, Dict, Optional

class Permission(Enum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    ADMIN = "ADMIN"

class Task138:
    MAX_USERNAME_LENGTH = 50
    MIN_PASSWORD_LENGTH = 8
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
    MAX_LOGIN_ATTEMPTS = 3
    
    class User:
        def __init__(self, username: str, password: str, permissions: Set[Permission]):
            if not Task138._is_valid_username(username):
                raise ValueError("Invalid username format")
            if not Task138._is_valid_password(password):
                raise ValueError(f"Password must be at least {Task138.MIN_PASSWORD_LENGTH} characters")
            
            self.username = username
            self.salt = Task138._generate_salt()
            self.password_hash = Task138._hash_password(password, self.salt)
            self.permissions = set(permissions)
        
        def verify_password(self, password: str) -> bool:
            if password is None:
                return False
            hash_attempt = Task138._hash_password(password, self.salt)
            return secrets.compare_digest(hash_attempt, self.password_hash)
        
        def get_permissions(self) -> Set[Permission]:
            return self.permissions.copy()
    
    class PermissionManager:
        def __init__(self):
            self.users: Dict[str, Task138.User] = {}
            self.login_attempts: Dict[str, int] = {}
        
        def add_user(self, username: str, password: str, permissions: Set[Permission]) -> bool:
            try:
                if username is None or password is None or permissions is None:
                    return False
                
                if username in self.users:
                    return False
                
                user = Task138.User(username, password, permissions)
                self.users[username] = user
                return True
            except Exception:
                return False
        
        def authenticate(self, username: str, password: str) -> bool:
            try:
                if username is None or password is None:
                    return False
                
                if self.login_attempts.get(username, 0) >= Task138.MAX_LOGIN_ATTEMPTS:
                    return False
                
                user = self.users.get(username)
                if user is None:
                    self._record_failed_attempt(username)
                    return False
                
                if user.verify_password(password):
                    if username in self.login_attempts:
                        del self.login_attempts[username]
                    return True
                else:
                    self._record_failed_attempt(username)
                    return False
            except Exception:
                return False
        
        def has_permission(self, username: str, permission: Permission) -> bool:
            if username is None or permission is None:
                return False
            
            user = self.users.get(username)
            if user is None:
                return False
            
            return permission in user.permissions or Permission.ADMIN in user.permissions
        
        def grant_permission(self, admin_username: str, target_username: str, permission: Permission) -> bool:
            if not self.has_permission(admin_username, Permission.ADMIN):
                return False
            
            user = self.users.get(target_username)
            if user is None or permission is None:
                return False
            
            user.permissions.add(permission)
            return True
        
        def revoke_permission(self, admin_username: str, target_username: str, permission: Permission) -> bool:
            if not self.has_permission(admin_username, Permission.ADMIN):
                return False
            
            user = self.users.get(target_username)
            if user is None or permission is None:
                return False
            
            user.permissions.discard(permission)
            return True
        
        def _record_failed_attempt(self, username: str):
            self.login_attempts[username] = self.login_attempts.get(username, 0) + 1
    
    @staticmethod
    def _is_valid_username(username: str) -> bool:
        if username is None or len(username) > Task138.MAX_USERNAME_LENGTH:
            return False
        return Task138.USERNAME_PATTERN.match(username) is not None
    
    @staticmethod
    def _is_valid_password(password: str) -> bool:
        return password is not None and len(password) >= Task138.MIN_PASSWORD_LENGTH
    
    @staticmethod
    def _generate_salt() -> str:
        salt_bytes = secrets.token_bytes(16)
        return base64.b64encode(salt_bytes).decode('utf-8')
    
    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        hash_obj = hashlib.sha256()
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(password.encode('utf-8'))
        return base64.b64encode(hash_obj.digest()).decode('utf-8')

def main():
    manager = Task138.PermissionManager()
    
    # Test Case 1: Add admin user
    result1 = manager.add_user("admin", "Admin@1234", {Permission.ADMIN})
    print(f"Test 1 - Add admin user: {'PASSED' if result1 else 'FAILED'}")
    
    # Test Case 2: Add regular user with READ permission
    result2 = manager.add_user("user1", "User@12345", {Permission.READ})
    print(f"Test 2 - Add regular user: {'PASSED' if result2 else 'FAILED'}")
    
    # Test Case 3: Authenticate user
    result3 = manager.authenticate("admin", "Admin@1234")
    print(f"Test 3 - Authenticate admin: {'PASSED' if result3 else 'FAILED'}")
    
    # Test Case 4: Check permission
    result4 = manager.has_permission("user1", Permission.READ)
    print(f"Test 4 - User1 has READ permission: {'PASSED' if result4 else 'FAILED'}")
    
    # Test Case 5: Grant permission
    result5 = manager.grant_permission("admin", "user1", Permission.WRITE)
    has_write = manager.has_permission("user1", Permission.WRITE)
    print(f"Test 5 - Admin grants WRITE to user1: {'PASSED' if result5 and has_write else 'FAILED'}")

if __name__ == "__main__":
    main()
