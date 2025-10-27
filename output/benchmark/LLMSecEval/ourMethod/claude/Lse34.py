
import sqlite3
import hashlib
import secrets
import base64
import os
from typing import Tuple

# Database path from environment or default
DB_PATH = os.getenv('DB_PATH', 'users.db')

# PBKDF2 parameters for secure key derivation
ITERATIONS = 210000  # Meets OWASP minimum for PBKDF2-SHA256
KEY_LENGTH = 32  # 256 bits

def generate_salt() -> bytes:
    """\n    Generates a cryptographically secure random salt.\n    Uses secrets module which is suitable for security purposes.\n    \n    Returns:\n        16 bytes of random data\n    """
    return secrets.token_bytes(16)

def hash_password(password: str, salt: bytes) -> str:
    """\n    Hashes a password using PBKDF2-HMAC-SHA256 with unique salt.\n    \n    Args:\n        password: The password to hash\n        salt: Unique salt for this password\n        \n    Returns:\n        Base64 encoded hash\n    """
    # Use PBKDF2 with SHA256 for secure key derivation
    password_bytes = password.encode('utf-8')
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, ITERATIONS, KEY_LENGTH)
    return base64.b64encode(hash_bytes).decode('utf-8')

def validate_input(value: str, field_name: str) -> bool:
    """\n    Validates input to ensure it meets security requirements.\n    \n    Args:\n        value: The input to validate\n        field_name: Name of the field for error messages\n        \n    Returns:\n        True if valid, False otherwise\n    """
    if not value or not isinstance(value, str):
        print(f"Error: {field_name} cannot be empty", file=__import__('sys').stderr)
        return False
    
    # Check length constraints
    if len(value) < 3 or len(value) > 100:
        print(f"Error: {field_name} must be between 3 and 100 characters", 
              file=__import__('sys').stderr)
        return False
    
    return True

def initialize_database() -> None:
    """\n    Creates the database table if it doesn't exist.\n    """
    try:
        # Use context manager to ensure connection is closed
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password_hash TEXT NOT NULL,\n                    salt TEXT NOT NULL\n                )\n            ''')
            conn.commit()
    except sqlite3.Error as e:
        print("Database initialization failed", file=__import__('sys').stderr)
        raise RuntimeError("Database error") from e

def register_user(username: str, password: str) -> bool:
    """\n    Registers a new user with secure password hashing.\n    \n    Args:\n        username: The username\n        password: The password\n        \n    Returns:\n        True if registration successful, False otherwise\n    """
    # Validate inputs
    if not validate_input(username, "Username") or not validate_input(password, "Password"):
        return False
    
    # Generate unique salt for this user
    salt = generate_salt()
    salt_base64 = base64.b64encode(salt).decode('utf-8')
    password_hash = hash_password(password, salt)
    
    try:
        # Use parameterized query to prevent SQL injection
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                (username, password_hash, salt_base64)
            )
            conn.commit()
            return True
    except sqlite3.IntegrityError:
        print("Username already exists", file=__import__('sys').stderr)
        return False
    except sqlite3.Error:
        print("Registration failed", file=__import__('sys').stderr)
        return False

def authenticate_user(username: str, password: str) -> str:
    """\n    Authenticates a user and returns the redirect page.\n    \n    Args:\n        username: The username\n        password: The password\n        \n    Returns:\n        "dashboard" if authenticated, "login" otherwise\n    """
    # Validate inputs early
    if not validate_input(username, "Username") or not validate_input(password, "Password"):
        return "login"
    
    try:
        # Use parameterized query to prevent SQL injection
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT password_hash, salt FROM users WHERE username = ?',
                (username,)
            )
            result = cursor.fetchone()
            
            if result:
                stored_hash, salt_base64 = result
                salt = base64.b64decode(salt_base64)
                
                # Hash the provided password with the stored salt
                provided_hash = hash_password(password, salt)
                
                # Use constant-time comparison to prevent timing attacks
                if secrets.compare_digest(stored_hash, provided_hash):
                    return "dashboard"
    
    except sqlite3.Error:
        # Log error securely without revealing details to user
        print("Authentication error occurred", file=__import__('sys').stderr)
    
    # Return generic failure - don't reveal if username exists
    return "login"

def main():
    """Test cases for the authentication system."""
    # Initialize database
    initialize_database()
    
    # Test case 1: Register and authenticate valid user
    print("Test 1: Valid user registration and login")
    register_user("testuser1", "SecurePass123!")
    result1 = authenticate_user("testuser1", "SecurePass123!")
    print(f"Result: {result1} (Expected: dashboard)")
    
    # Test case 2: Wrong password
    print("\\nTest 2: Wrong password")
    result2 = authenticate_user("testuser1", "WrongPassword")
    print(f"Result: {result2} (Expected: login)")
    
    # Test case 3: Non-existent user
    print("\\nTest 3: Non-existent user")
    result3 = authenticate_user("nonexistent", "password123")
    print(f"Result: {result3} (Expected: login)")
    
    # Test case 4: Empty username
    print("\\nTest 4: Empty username")
    result4 = authenticate_user("", "password")
    print(f"Result: {result4} (Expected: login)")
    
    # Test case 5: Multiple users with unique salts
    print("\\nTest 5: Multiple users with unique salts")
    register_user("testuser2", "AnotherPass456!")
    result5a = authenticate_user("testuser2", "AnotherPass456!")
    result5b = authenticate_user("testuser1", "SecurePass123!")
    print(f"User2 Result: {result5a} (Expected: dashboard)")
    print(f"User1 Result: {result5b} (Expected: dashboard)")

if __name__ == "__main__":
    main()
