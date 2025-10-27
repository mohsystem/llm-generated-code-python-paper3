
import hashlib
import secrets
import base64
import os
from typing import Optional, Dict

class Lse96:
    SALT_LENGTH = 16
    ITERATIONS = 100000
    HASH_ALGORITHM = 'sha256'
    
    # Simulated database
    database: Dict[str, str] = {}
    
    @staticmethod
    def generate_salt() -> str:
        """Generate a cryptographically secure random salt"""
        salt = secrets.token_bytes(Lse96.SALT_LENGTH)
        return base64.b64encode(salt).decode('utf-8')
    
    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """Hash password using PBKDF2 with SHA-256"""
        salt_bytes = base64.b64decode(salt)
        password_hash = hashlib.pbkdf2_hmac(
            Lse96.HASH_ALGORITHM,
            password.encode('utf-8'),
            salt_bytes,
            Lse96.ITERATIONS
        )
        return base64.b64encode(password_hash).decode('utf-8')
    
    @staticmethod
    def register_user(username: str, password: str) -> bool:
        """Register a new user with username and password"""
        if not username or not username.strip():
            return False
        if not password or len(password) < 8:
            return False
        
        try:
            salt = Lse96.generate_salt()
            hashed_password = Lse96.hash_password(password, salt)
            stored_value = f"{salt}:{hashed_password}"
            
            # Simulated database storage
            Lse96.database[username] = stored_value
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
    
    @staticmethod
    def verify_user(username: str, password: str) -> bool:
        """Verify user credentials"""
        stored_value = Lse96.database.get(username)
        if not stored_value:
            return False
        
        try:
            salt, stored_hash = stored_value.split(':')
            computed_hash = Lse96.hash_password(password, salt)
            return secrets.compare_digest(stored_hash, computed_hash)
        except Exception as e:
            print(f"Error: {e}")
            return False

def main():
    # Test Case 1: Valid registration
    print("Test 1 - Valid registration:", 
          Lse96.register_user("user1", "SecurePass123!"))
    
    # Test Case 2: Valid registration and verification
    Lse96.register_user("user2", "MyP@ssw0rd")
    print("Test 2 - Valid login:", 
          Lse96.verify_user("user2", "MyP@ssw0rd"))
    
    # Test Case 3: Invalid password (too short)
    print("Test 3 - Short password:", 
          Lse96.register_user("user3", "short"))
    
    # Test Case 4: Invalid login
    Lse96.register_user("user4", "ValidPass123")
    print("Test 4 - Wrong password:", 
          Lse96.verify_user("user4", "WrongPass123"))
    
    # Test Case 5: Empty username
    print("Test 5 - Empty username:", 
          Lse96.register_user("", "ValidPass123"))

if __name__ == "__main__":
    main()
