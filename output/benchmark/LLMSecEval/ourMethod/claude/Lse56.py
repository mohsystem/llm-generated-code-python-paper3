
import hashlib
import secrets
import re
from typing import Dict, Optional

# Simulated user database - in production, use a proper database with encrypted credentials
class User:
    def __init__(self, email: str, password: str):
        self.email = email
        self.salt = self._generate_salt()
        self.password_hash = self._hash_password(password, self.salt)
        self.logged_in = False
    
    @staticmethod
    def _generate_salt() -> bytes:
        """Generate cryptographically secure random salt"""
        return secrets.token_bytes(16)
    
    @staticmethod
    def _hash_password(password: str, salt: bytes) -> bytes:
        """Hash password using PBKDF2-HMAC-SHA256 with 210000 iterations"""
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 210000)
    
    def verify_password(self, password: str) -> bool:
        """Verify password using constant-time comparison"""
        provided_hash = self._hash_password(password, self.salt)
        return secrets.compare_digest(self.password_hash, provided_hash)


users: Dict[str, User] = {}


def is_valid_email(email: str) -> bool:
    """Validate email format"""
    if not email or len(email) > 254:
        return False
    # Basic email validation pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def sanitize_input(input_str: Optional[str]) -> str:
    """Sanitize input to prevent injection attacks"""
    if not input_str:
        return ""
    # Remove control characters and limit length
    sanitized = re.sub(r'[\\x00-\\x1F\\x7F]', '', input_str)
    return sanitized[:254]


def register_user(email: str, password: str) -> str:
    """Register a new user"""
    # Input validation
    email = sanitize_input(email)
    if not is_valid_email(email):
        return "Error: Invalid email format"
    
    if not password or len(password) < 8:
        return "Error: Password must be at least 8 characters"
    
    if email in users:
        return "Error: User already exists"
    
    users[email] = User(email, password)
    return "Success: User registered"


def login(email: str, password: str) -> str:
    """Login user"""
    # Input validation and sanitization
    email = sanitize_input(email)
    if not is_valid_email(email):
        return "Error: Invalid credentials"
    
    if not password:
        return "Error: Invalid credentials"
    
    user = users.get(email)
    if not user:
        return "Error: Invalid credentials"
    
    # Verify password using constant-time comparison
    if not user.verify_password(password):
        return "Error: Invalid credentials"
    
    user.logged_in = True
    return "Success: Logged in"


def change_email(old_email: str, new_email: str, password: str) -> str:
    """Change email - requires authentication"""
    # Input validation and sanitization
    old_email = sanitize_input(old_email)
    new_email = sanitize_input(new_email)
    
    if not is_valid_email(old_email) or not is_valid_email(new_email):
        return "Error: Invalid email format"
    
    if not password:
        return "Error: Password required"
    
    # Check if user exists
    user = users.get(old_email)
    if not user:
        return "Error: User not found"
    
    # Check if user is logged in
    if not user.logged_in:
        return "Error: User must be logged in"
    
    # Verify password using constant-time comparison
    if not user.verify_password(password):
        return "Error: Incorrect password"
    
    # Check if new email is different from old email
    if old_email == new_email:
        return "Error: New email must be different from old email"
    
    # Check if new email already exists
    if new_email in users:
        return "Error: New email already in use"
    
    # Update email
    del users[old_email]
    user.email = new_email
    users[new_email] = user
    
    return "Success: Email changed"


def logout(email: str) -> str:
    """Logout user"""
    email = sanitize_input(email)
    user = users.get(email)
    if user:
        user.logged_in = False
        return "Success: Logged out"
    return "Error: User not found"


if __name__ == "__main__":
    # Test Case 1: Register and login
    print("Test 1: Register and Login")
    print(register_user("user1@example.com", "SecurePass123!"))
    print(login("user1@example.com", "SecurePass123!"))
    
    # Test Case 2: Change email with valid credentials
    print("\\nTest 2: Change email successfully")
    print(change_email("user1@example.com", "newuser1@example.com", "SecurePass123!"))
    
    # Test Case 3: Try to change email without being logged in
    print("\\nTest 3: Change email without login")
    print(register_user("user2@example.com", "Password456!"))
    print(change_email("user2@example.com", "newuser2@example.com", "Password456!"))
    
    # Test Case 4: Try to change email with wrong password
    print("\\nTest 4: Change email with wrong password")
    print(register_user("user3@example.com", "MyPass789!"))
    print(login("user3@example.com", "MyPass789!"))
    print(change_email("user3@example.com", "newuser3@example.com", "WrongPassword"))
    
    # Test Case 5: Try to change to same email
    print("\\nTest 5: Change to same email")
    print(register_user("user4@example.com", "TestPass000!"))
    print(login("user4@example.com", "TestPass000!"))
    print(change_email("user4@example.com", "user4@example.com", "TestPass000!"))
