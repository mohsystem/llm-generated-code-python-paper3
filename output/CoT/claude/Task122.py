
import hashlib
import secrets
import base64
from typing import Dict, Tuple

class Task122:
    def __init__(self):
        self.user_database: Dict[str, Tuple[str, str]] = {}
        self.SALT_LENGTH = 16
        self.ITERATIONS = 10000
    
    def generate_salt(self) -> str:
        salt = secrets.token_bytes(self.SALT_LENGTH)
        return base64.b64encode(salt).decode('utf-8')
    
    def hash_password(self, password: str, salt: str) -> str:
        salt_bytes = base64.b64decode(salt)
        pwd_hash = hashlib.sha256(salt_bytes + password.encode()).digest()
        
        for _ in range(self.ITERATIONS):
            pwd_hash = hashlib.sha256(pwd_hash).digest()
        
        return base64.b64encode(pwd_hash).decode('utf-8')
    
    def validate_password(self, password: str) -> bool:
        if not password or len(password) < 8:
            return False
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        return has_upper and has_lower and has_digit and has_special
    
    def signup_user(self, username: str, password: str) -> str:
        if not username or not username.strip():
            return "Error: Username cannot be empty"
        
        if username in self.user_database:
            return "Error: Username already exists"
        
        if not self.validate_password(password):
            return "Error: Password must be at least 8 characters and contain uppercase, lowercase, digit, and special character"
        
        salt = self.generate_salt()
        password_hash = self.hash_password(password, salt)
        
        self.user_database[username] = (password_hash, salt)
        
        return "Success: User registered successfully"
    
    def verify_login(self, username: str, password: str) -> bool:
        if username not in self.user_database:
            return False
        
        stored_hash, salt = self.user_database[username]
        hashed_attempt = self.hash_password(password, salt)
        
        return hashed_attempt == stored_hash

def main():
    auth_system = Task122()
    
    print("Test Case 1: Valid signup")
    print(auth_system.signup_user("john_doe", "SecurePass123!"))
    
    print("\\nTest Case 2: Duplicate username")
    print(auth_system.signup_user("john_doe", "AnotherPass456@"))
    
    print("\\nTest Case 3: Weak password")
    print(auth_system.signup_user("jane_doe", "weak"))
    
    print("\\nTest Case 4: Valid signup")
    print(auth_system.signup_user("alice_smith", "MyP@ssw0rd!"))
    
    print("\\nTest Case 5: Empty username")
    print(auth_system.signup_user("", "ValidPass123!"))
    
    print("\\nLogin Verification Test:")
    print(f"Correct password: {auth_system.verify_login('john_doe', 'SecurePass123!')}")
    print(f"Wrong password: {auth_system.verify_login('john_doe', 'WrongPass123!')}")

if __name__ == "__main__":
    main()
