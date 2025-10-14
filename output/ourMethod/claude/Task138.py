
import secrets
import os
from typing import Set, Optional, Dict
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac

MAGIC = b"ENC1"
VERSION = 1
SALT_LENGTH = 16
IV_LENGTH = 12
TAG_LENGTH = 16
ITERATIONS = 210000


class User:
    def __init__(self, username: str, password_hash: bytes, salt: bytes, permissions: Set[str]):
        if not username or not username.strip():
            raise ValueError("Username cannot be empty")
        if not password_hash:
            raise ValueError("Password hash cannot be empty")
        if not salt or len(salt) != SALT_LENGTH:
            raise ValueError(f"Salt must be {SALT_LENGTH} bytes")
        
        self.username = username
        self.password_hash = bytes(password_hash)
        self.salt = bytes(salt)
        self.permissions = set(permissions) if permissions else set()
    
    def get_permissions(self) -> Set[str]:
        return self.permissions.copy()


class PermissionManager:
    def __init__(self):
        self.users: Dict[str, User] = {}
    
    def _hash_password(self, password: str, salt: bytes) -> bytes:
        if not password:
            raise ValueError("Password cannot be empty")
        if not salt or len(salt) != SALT_LENGTH:
            raise ValueError(f"Salt must be {SALT_LENGTH} bytes")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        if not a or not b or len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
    
    def _is_password_complex(self, password: str) -> bool:
        if not password or len(password) < 8:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        return has_upper and has_lower and has_digit and has_special
    
    def create_user(self, username: str, password: str, permissions: Optional[Set[str]] = None) -> bool:
        if not username or not username.strip():
            return False
        if not password or len(password) < 8:
            return False
        if not self._is_password_complex(password):
            return False
        
        normalized_username = username.strip().lower()
        if len(normalized_username) > 50:
            return False
        
        if normalized_username in self.users:
            return False
        
        salt = secrets.token_bytes(SALT_LENGTH)
        password_hash = self._hash_password(password, salt)
        
        validated_permissions = set()
        if permissions:
            for perm in permissions:
                if perm and perm.strip() and len(perm) <= 50:
                    validated_permissions.add(perm.strip())
        
        user = User(normalized_username, password_hash, salt, validated_permissions)
        self.users[normalized_username] = user
        return True
    
    def authenticate(self, username: str, password: str) -> bool:
        if not username or not password:
            return False
        
        normalized_username = username.strip().lower()
        user = self.users.get(normalized_username)
        if not user:
            return False
        
        provided_hash = self._hash_password(password, user.salt)
        return self._constant_time_compare(provided_hash, user.password_hash)
    
    def grant_permission(self, username: str, permission: str) -> bool:
        if not username or not permission or not permission.strip():
            return False
        if len(permission) > 50:
            return False
        
        normalized_username = username.strip().lower()
        user = self.users.get(normalized_username)
        if not user:
            return False
        
        user.permissions.add(permission.strip())
        return True
    
    def revoke_permission(self, username: str, permission: str) -> bool:
        if not username or not permission:
            return False
        
        normalized_username = username.strip().lower()
        user = self.users.get(normalized_username)
        if not user:
            return False
        
        try:
            user.permissions.remove(permission.strip())
            return True
        except KeyError:
            return False
    
    def has_permission(self, username: str, permission: str) -> bool:
        if not username or not permission:
            return False
        
        normalized_username = username.strip().lower()
        user = self.users.get(normalized_username)
        if not user:
            return False
        
        return permission.strip() in user.permissions
    
    def get_user_permissions(self, username: str) -> Set[str]:
        if not username:
            return set()
        
        normalized_username = username.strip().lower()
        user = self.users.get(normalized_username)
        if not user:
            return set()
        
        return user.get_permissions()


def main():
    manager = PermissionManager()
    
    print("Test 1: Create user with valid password")
    result1 = manager.create_user("alice", "Pass@123", {"read", "write"})
    print(f"User created: {result1}")
    
    print("\\nTest 2: Authenticate with correct credentials")
    result2 = manager.authenticate("alice", "Pass@123")
    print(f"Authentication successful: {result2}")
    
    print("\\nTest 3: Authenticate with incorrect password")
    result3 = manager.authenticate("alice", "WrongPass")
    print(f"Authentication successful: {result3}")
    
    print("\\nTest 4: Grant and check permission")
    manager.grant_permission("alice", "admin")
    result4 = manager.has_permission("alice", "admin")
    print(f"Has admin permission: {result4}")
    
    print("\\nTest 5: Revoke permission and check")
    manager.revoke_permission("alice", "write")
    permissions = manager.get_user_permissions("alice")
    print(f"Remaining permissions: {permissions}")


if __name__ == "__main__":
    main()
