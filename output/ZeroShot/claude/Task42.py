
import hashlib
import secrets
import base64
from typing import Dict, Optional

class Task42:
    def __init__(self):
        self.user_database: Dict[str, Dict[str, str]] = {}
    
    def _generate_salt(self) -> str:
        """Generate a cryptographically secure random salt."""
        salt = secrets.token_bytes(16)
        return base64.b64encode(salt).decode('utf-8')
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using SHA-256."""
        salt_bytes = base64.b64decode(salt.encode('utf-8'))
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt_bytes,
            100000  # iterations
        )
        return base64.b64encode(password_hash).decode('utf-8')
    
    def register_user(self, username: str, password: str) -> bool:
        """Register a new user with username and password."""
        if not username or not username.strip() or not password or len(password) < 8:
            return False
        
        if username in self.user_database:
            return False
        
        salt = self._generate_salt()
        password_hash = self._hash_password(password, salt)
        
        self.user_database[username] = {
            'password_hash': password_hash,
            'salt': salt
        }
        return True
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate user with username and password."""
        if not username or not password:
            return False
        
        credentials = self.user_database.get(username)
        if not credentials:
            return False
        
        hashed_input = self._hash_password(password, credentials['salt'])
        return secrets.compare_digest(hashed_input, credentials['password_hash'])
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change user password."""
        if not self.authenticate_user(username, old_password):
            return False
        
        if not new_password or len(new_password) < 8:
            return False
        
        salt = self._generate_salt()
        password_hash = self._hash_password(new_password, salt)
        
        self.user_database[username] = {
            'password_hash': password_hash,
            'salt': salt
        }
        return True


def main():
    auth_system = Task42()
    
    # Test Case 1: Register new user
    print(f"Test 1 - Register user 'alice': {auth_system.register_user('alice', 'SecurePass123')}")
    
    # Test Case 2: Authenticate valid user
    print(f"Test 2 - Login alice with correct password: {auth_system.authenticate_user('alice', 'SecurePass123')}")
    
    # Test Case 3: Authenticate with wrong password
    print(f"Test 3 - Login alice with wrong password: {auth_system.authenticate_user('alice', 'WrongPass123')}")
    
    # Test Case 4: Register duplicate username
    print(f"Test 4 - Register duplicate user 'alice': {auth_system.register_user('alice', 'AnotherPass123')}")
    
    # Test Case 5: Change password
    auth_system.register_user('bob', 'OldPassword123')
    print(f"Test 5 - Change bob's password: {auth_system.change_password('bob', 'OldPassword123', 'NewPassword123')}")
    print(f"Test 5 - Login bob with new password: {auth_system.authenticate_user('bob', 'NewPassword123')}")


if __name__ == "__main__":
    main()
