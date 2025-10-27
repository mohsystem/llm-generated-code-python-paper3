
import sqlite3
import hashlib
import secrets
import base64
import re
from typing import Tuple

# Constants for salt generation
SALT_LENGTH = 16  # 128-bit salt

def generate_salt() -> str:
    """\n    Generates a cryptographically secure random salt.\n    Uses secrets module for cryptographic strength.\n    Returns base64-encoded salt string.\n    """
    salt_bytes = secrets.token_bytes(SALT_LENGTH)
    return base64.b64encode(salt_bytes).decode('utf-8')

def hash_password(password: str, salt: str) -> str:
    """\n    Hashes password with salt using SHA-256.\n    Note: For production, use bcrypt, scrypt, or Argon2id from the cryptography library.\n    This implementation demonstrates the salting concept.\n    \n    Args:\n        password: Plain text password\n        salt: Unique salt for this password\n    \n    Returns:\n        Base64-encoded hash\n    """
    salted_password = password + salt
    hash_obj = hashlib.sha256(salted_password.encode('utf-8'))
    return base64.b64encode(hash_obj.digest()).decode('utf-8')

def is_valid_username(username: str) -> bool:
    """\n    Validates username input to prevent SQL injection and ensure format.\n    Accepts only alphanumeric characters, underscore, and hyphen.\n    Length between 3 and 50 characters.\n    \n    Args:\n        username: Input username\n    \n    Returns:\n        True if valid, False otherwise\n    """
    if not username or len(username) < 3 or len(username) > 50:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))

def is_valid_password(password: str) -> bool:
    """\n    Validates password input to ensure it meets security requirements.\n    Minimum 8 characters, maximum 128 characters.\n    \n    Args:\n        password: Input password\n    \n    Returns:\n        True if valid, False otherwise\n    """
    if not password or len(password) < 8 or len(password) > 128:
        return False
    return True

def insert_user(username: str, password: str) -> bool:
    """\n    Inserts username and hashed password into database.\n    Uses parameterized queries to prevent SQL injection.\n    Stores both the hash and salt for future verification.\n    \n    Args:\n        username: Validated username\n        password: Plain text password (will be hashed)\n    \n    Returns:\n        True if insertion successful, False otherwise\n    """
    # Validate inputs before processing
    if not is_valid_username(username):
        print("Invalid username format", file=__import__('sys').stderr)
        return False
    
    if not is_valid_password(password):
        print("Invalid password format", file=__import__('sys').stderr)
        return False
    
    # Generate unique salt for this password
    salt = generate_salt()
    
    # Hash password with salt
    hashed_password = hash_password(password, salt)
    
    # Use context manager to ensure proper resource cleanup
    try:
        with sqlite3.connect(':memory:') as conn:
            cursor = conn.cursor()
            
            # Create table if not exists
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password_hash TEXT NOT NULL,\n                    salt TEXT NOT NULL\n                )\n            ''')
            
            # Use parameterized query to prevent SQL injection
            cursor.execute(
                'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                (username, hashed_password, salt)
            )
            
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error as e:
        print("Database error occurred", file=__import__('sys').stderr)
        return False

def main():
    """Main function with test cases"""
    # Test case 1: Valid username and password
    print(f"Test 1: {insert_user('john_doe', 'SecurePass123!')}")
    
    # Test case 2: Another valid user
    print(f"Test 2: {insert_user('jane-smith', 'MyP@ssw0rd2024')}")
    
    # Test case 3: Invalid username (too short)
    print(f"Test 3: {insert_user('ab', 'ValidPassword1')}")
    
    # Test case 4: Invalid password (too short)
    print(f"Test 4: {insert_user('validuser', 'short')}")
    
    # Test case 5: Valid edge case username and password
    print(f"Test 5: {insert_user('user123', 'LongPassword123456')}")

if __name__ == '__main__':
    main()
