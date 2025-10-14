
import hashlib
import secrets
import base64
import re
from typing import Dict, Optional

class Task136:
    SALT_LENGTH = 16
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
    PASSWORD_PATTERN = re.compile(r'^.{8,}$')
    MAX_LOGIN_ATTEMPTS = 3
    
    def __init__(self):
        self.user_database: Dict[str, dict] = {}
        self.login_attempts: Dict[str, int] = {}
    
    def generate_salt(self) -> str:
        salt = secrets.token_bytes(self.SALT_LENGTH)
        return base64.b64encode(salt).decode('utf-8')
    
    def hash_password(self, password: str, salt: str) -> str:
        salt_bytes = base64.b64decode(salt.encode('utf-8'))
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100000)
        return base64.b64encode(hashed).decode('utf-8')
    
    def validate_username(self, username: Optional[str]) -> bool:
        if not username:
            return False
        return bool(self.USERNAME_PATTERN.match(username))
    
    def validate_password(self, password: Optional[str]) -> bool:
        if not password:
            return False
        return bool(self.PASSWORD_PATTERN.match(password))
    
    def register_user(self, username: str, password: str) -> str:
        if not self.validate_username(username):
            return "Invalid username. Must be 3-20 alphanumeric characters or underscore."
        
        if not self.validate_password(password):
            return "Invalid password. Must be at least 8 characters long."
        
        if username in self.user_database:
            return "Username already exists."
        
        salt = self.generate_salt()
        hashed_password = self.hash_password(password, salt)
        
        self.user_database[username] = {
            'username': username,
            'hashed_password': hashed_password,
            'salt': salt
        }
        self.login_attempts[username] = 0
        
        return "User registered successfully."
    
    def constant_time_equals(self, a: Optional[str], b: Optional[str]) -> bool:
        if a is None or b is None:
            return False
        
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0
    
    def authenticate_user(self, username: str, password: str) -> str:
        if not self.validate_username(username):
            return "Authentication failed."
        
        if self.login_attempts.get(username, 0) >= self.MAX_LOGIN_ATTEMPTS:
            return "Account locked due to too many failed attempts."
        
        user_cred = self.user_database.get(username)
        
        if user_cred is None:
            # Perform dummy hash to prevent timing attacks
            self.hash_password(password, self.generate_salt())
            return "Authentication failed."
        
        hashed_input_password = self.hash_password(password, user_cred['salt'])
        
        if self.constant_time_equals(hashed_input_password, user_cred['hashed_password']):
            self.login_attempts[username] = 0
            return "Authentication successful."
        else:
            attempts = self.login_attempts.get(username, 0) + 1
            self.login_attempts[username] = attempts
            
            if attempts >= self.MAX_LOGIN_ATTEMPTS:
                return "Account locked due to too many failed attempts."
            
            return "Authentication failed."
    
    def reset_login_attempts(self, username: str) -> str:
        if username in self.user_database:
            self.login_attempts[username] = 0
            return "Login attempts reset successfully."
        return "User not found."


def main():
    auth = Task136()
    
    print("=== Test Case 1: Valid User Registration ===")
    print(auth.register_user("john_doe", "SecurePass123"))
    
    print("\\n=== Test Case 2: Invalid Username (too short) ===")
    print(auth.register_user("ab", "SecurePass123"))
    
    print("\\n=== Test Case 3: Invalid Password (too short) ===")
    print(auth.register_user("jane_doe", "short"))
    
    print("\\n=== Test Case 4: Successful Authentication ===")
    print(auth.authenticate_user("john_doe", "SecurePass123"))
    
    print("\\n=== Test Case 5: Failed Authentication and Account Lockout ===")
    print(auth.authenticate_user("john_doe", "WrongPass1"))
    print(auth.authenticate_user("john_doe", "WrongPass2"))
    print(auth.authenticate_user("john_doe", "WrongPass3"))
    print(auth.authenticate_user("john_doe", "SecurePass123"))
    print(auth.reset_login_attempts("john_doe"))
    print(auth.authenticate_user("john_doe", "SecurePass123"))


if __name__ == "__main__":
    main()
