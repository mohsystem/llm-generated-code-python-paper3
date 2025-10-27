
import os
import secrets
import hashlib
import sqlite3
import re
from typing import Optional

# Constants for PBKDF2 (Rule #8, #9)
ITERATIONS = 210000  # PBKDF2 iterations >= 210000
KEY_LENGTH = 32  # 256-bit derived key
SALT_LENGTH = 16  # 16-byte salt

def generate_salt() -> bytes:
    """Generate cryptographically secure random salt (Rule #11)"""
    return secrets.token_bytes(SALT_LENGTH)

def hash_password(password: str, salt: bytes) -> str:
    """\n    Hash password using PBKDF2-HMAC-SHA256 with unique salt\n    (Rule #8, #9, #10)\n    """
    # Use PBKDF2-HMAC-SHA256 for secure key derivation
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, KEY_LENGTH)
    
    # Store salt + hash together
    combined = salt + key
    return combined.hex()

def validate_username(username: str) -> bool:
    """Validate username format and length (Rule #3)"""
    if not username or len(username) > 50:
        return False
    # Only allow alphanumeric, underscore, and hyphen
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))

def validate_password(password: str) -> bool:
    """Validate password meets security requirements (Rule #13)"""
    if not password or len(password) < 12 or len(password) > 128:
        return False
    return True

def register_user(username: str, password: str) -> bool:
    """\n    Register a new user with secure password hashing\n    (Rule #1, #3, #8, #9, #10, #13, #14, #15)\n    """
    # Input validation (Rule #3)
    if not validate_username(username):
        print("Invalid username", file=os.sys.stderr)
        return False
    
    # Strong password policy (Rule #13)
    if not validate_password(password):
        print("Password must be between 12 and 128 characters", file=os.sys.stderr)
        return False
    
    try:
        # Get database path from environment (Rule #14, #15)
        db_path = os.getenv('DB_PATH', ':memory:')
        
        # Generate unique salt for this password (Rule #10, #11)
        salt = generate_salt()
        
        # Hash password with salt (Rule #8, #9)
        hashed_password = hash_password(password, salt)
        
        # Use parameterized query to prevent SQL injection (Rule #3)
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Create table if not exists
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password_hash TEXT NOT NULL\n                )\n            ''')
            
            # Insert user with parameterized query
            cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, hashed_password)
            )
            conn.commit()
            return True
            
    except sqlite3.IntegrityConstraintError:
        # Generic error message to avoid information leakage (Rule #1)
        print("Registration failed", file=os.sys.stderr)
        return False
    except Exception:
        # Generic error message (Rule #1)
        print("Registration failed", file=os.sys.stderr)
        return False

if __name__ == '__main__':
    # Test cases
    print("Test 1: Valid registration")
    print(register_user("testuser1", "SecurePass123!@#"))
    
    print("\\nTest 2: Valid registration with different user")
    print(register_user("testuser2", "AnotherSecure456$%^"))
    
    print("\\nTest 3: Invalid - password too short")
    print(register_user("testuser3", "short"))
    
    print("\\nTest 4: Invalid - empty username")
    print(register_user("", "ValidPassword123!"))
    
    print("\\nTest 5: Invalid - username with special chars")
    print(register_user("test@user", "ValidPassword123!"))
