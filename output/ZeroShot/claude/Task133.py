
import re
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, Optional

class Task133:
    TOKEN_LENGTH = 32
    TOKEN_EXPIRY_MINUTES = 15
    EMAIL_PATTERN = re.compile(r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')
    PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$')
    
    def __init__(self):
        self.users: Dict[str, dict] = {}
        self.reset_tokens: Dict[str, dict] = {}
    
    def generate_reset_token(self, email: str) -> str:
        if not email or not self.EMAIL_PATTERN.match(email):
            return "Error: Invalid email format"
        
        if email not in self.users:
            return "Error: Email not found"
        
        chars = string.ascii_letters + string.digits
        token = ''.join(secrets.choice(chars) for _ in range(self.TOKEN_LENGTH))
        
        expiry_time = datetime.now() + timedelta(minutes=self.TOKEN_EXPIRY_MINUTES)
        self.reset_tokens[token] = {
            'email': email,
            'expiry_time': expiry_time
        }
        
        return token
    
    def reset_password(self, token: str, new_password: str) -> str:
        if not token:
            return "Error: Token is required"
        
        if not new_password or not self.PASSWORD_PATTERN.match(new_password):
            return "Error: Password must be at least 8 characters with uppercase, lowercase, digit, and special character"
        
        if token not in self.reset_tokens:
            return "Error: Invalid token"
        
        token_data = self.reset_tokens[token]
        
        if datetime.now() > token_data['expiry_time']:
            del self.reset_tokens[token]
            return "Error: Token has expired"
        
        email = token_data['email']
        self.users[email]['password_hash'] = self._hash_password(new_password)
        del self.reset_tokens[token]
        
        return "Success: Password reset successfully"
    
    def _hash_password(self, password: str) -> str:
        return f"HASHED_{password}"
    
    def register_user(self, email: str, password: str) -> str:
        if not self.EMAIL_PATTERN.match(email):
            return "Error: Invalid email format"
        
        if email in self.users:
            return "Error: User already exists"
        
        self.users[email] = {'password_hash': self._hash_password(password)}
        return "Success: User registered"


def main():
    print("=== Password Reset Functionality Tests ===\\n")
    
    system = Task133()
    
    # Test Case 1: Register users
    print("Test 1: Register users")
    print(system.register_user("user1@example.com", "Password123!"))
    print(system.register_user("user2@example.com", "Secure456@"))
    print()
    
    # Test Case 2: Generate reset token for valid user
    print("Test 2: Generate reset token for valid user")
    token1 = system.generate_reset_token("user1@example.com")
    print(f"Token generated: {token1 if token1.startswith('Error') else f'Success (Length: {len(token1)})'}")
    print()
    
    # Test Case 3: Generate reset token for invalid email
    print("Test 3: Generate reset token for invalid email")
    print(system.generate_reset_token("invalidemail"))
    print()
    
    # Test Case 4: Reset password with valid token and valid password
    print("Test 4: Reset password with valid token")
    token2 = system.generate_reset_token("user2@example.com")
    if not token2.startswith("Error"):
        print(system.reset_password(token2, "NewPass789#"))
    print()
    
    # Test Case 5: Reset password with invalid token
    print("Test 5: Reset password with invalid token")
    print(system.reset_password("invalidtoken123", "ValidPass123!"))
    print()
    
    # Test Case 6: Reset password with weak password
    print("Test 6: Reset password with weak password")
    token3 = system.generate_reset_token("user1@example.com")
    if not token3.startswith("Error"):
        print(system.reset_password(token3, "weak"))


if __name__ == "__main__":
    main()
