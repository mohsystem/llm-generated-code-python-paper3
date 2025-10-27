
import hashlib
import secrets
import re
from typing import Dict, Optional

class Lse57:
    def __init__(self):
        self.user_database: Dict[str, Dict] = {}
        self.active_sessions: Dict[str, str] = {}
        self.email_pattern = re.compile(r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')
    
    def hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using SHA-256"""
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def generate_salt(self) -> str:
        """Generate a random salt"""
        return secrets.token_hex(16)
    
    def is_valid_email(self, email: str) -> bool:
        """Validate email format"""
        return email is not None and self.email_pattern.match(email) is not None
    
    def register_user(self, email: str, password: str) -> str:
        """Register a new user"""
        if not self.is_valid_email(email):
            return "Invalid email format"
        if password is None or len(password) < 8:
            return "Password must be at least 8 characters"
        if email in self.user_database:
            return "Email already exists"
        
        salt = self.generate_salt()
        password_hash = self.hash_password(password, salt)
        self.user_database[email] = {
            'email': email,
            'password_hash': password_hash,
            'salt': salt
        }
        return "Registration successful"
    
    def login(self, email: str, password: str) -> Optional[str]:
        """Login user and return session token"""
        if email not in self.user_database:
            return None
        
        user = self.user_database[email]
        password_hash = self.hash_password(password, user['salt'])
        
        if password_hash == user['password_hash']:
            session_token = secrets.token_urlsafe(32)
            self.active_sessions[session_token] = email
            return session_token
        return None
    
    def change_email(self, session_token: str, old_email: str, 
                    new_email: str, confirm_password: str) -> str:
        """Change user email with validation"""
        # Verify session
        if session_token is None or session_token not in self.active_sessions:
            return "User not logged in"
        
        logged_in_email = self.active_sessions[session_token]
        
        # Verify old email matches logged in user
        if logged_in_email != old_email:
            return "Old email does not match logged in user"
        
        # Verify old email exists
        if old_email not in self.user_database:
            return "Old email does not exist"
        
        # Validate new email format
        if not self.is_valid_email(new_email):
            return "Invalid new email format"
        
        # Check if new email already exists
        if new_email in self.user_database:
            return "New email already exists"
        
        # Verify confirm password
        user = self.user_database[old_email]
        password_hash = self.hash_password(confirm_password, user['salt'])
        
        if password_hash != user['password_hash']:
            return "Incorrect password"
        
        # Change email
        user['email'] = new_email
        self.user_database[new_email] = user
        del self.user_database[old_email]
        self.active_sessions[session_token] = new_email
        
        return "Email changed successfully"


def main():
    system = Lse57()
    
    print("=== Test Case 1: Successful email change ===")
    system.register_user("user1@example.com", "password123")
    token1 = system.login("user1@example.com", "password123")
    print(system.change_email(token1, "user1@example.com", 
                             "newuser1@example.com", "password123"))
    
    print("\\n=== Test Case 2: Invalid session token ===")
    print(system.change_email("invalid_token", "user2@example.com", 
                             "newuser2@example.com", "password123"))
    
    print("\\n=== Test Case 3: Incorrect password ===")
    system.register_user("user3@example.com", "password123")
    token3 = system.login("user3@example.com", "password123")
    print(system.change_email(token3, "user3@example.com", 
                             "newuser3@example.com", "wrongpassword"))
    
    print("\\n=== Test Case 4: New email already exists ===")
    system.register_user("user4@example.com", "password123")
    system.register_user("existing@example.com", "password123")
    token4 = system.login("user4@example.com", "password123")
    print(system.change_email(token4, "user4@example.com", 
                             "existing@example.com", "password123"))
    
    print("\\n=== Test Case 5: Invalid new email format ===")
    system.register_user("user5@example.com", "password123")
    token5 = system.login("user5@example.com", "password123")
    print(system.change_email(token5, "user5@example.com", 
                             "invalid-email", "password123"))


if __name__ == "__main__":
    main()
