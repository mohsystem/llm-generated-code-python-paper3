
import sqlite3
import secrets
import hashlib
import base64
from typing import Optional

# Constants for security configuration
SALT_LENGTH = 16  # 128 bits
PBKDF2_ITERATIONS = 210000
DB_PATH = 'users.db'

def generate_salt() -> bytes:
    """Generate cryptographically secure random salt using secrets module"""
    # Use secrets for CSPRNG, not random module
    return secrets.token_bytes(SALT_LENGTH)

def hash_password(password: str, salt: bytes) -> bytes:
    """Hash password using PBKDF2-HMAC-SHA256 with unique salt"""
    # Use PBKDF2 with SHA-256 and high iteration count
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)

def register_user(username: str, password: str) -> bool:
    """Register new user with validated inputs and secure password storage"""
    # Input validation - reject None, empty, or excessively long inputs
    if not username or not isinstance(username, str) or len(username) > 100:
        return False
    if not password or not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return False
    
    # Sanitize username - allow only alphanumeric and underscore
    if not username.replace('_', '').isalnum():
        return False
    
    try:
        # Use context manager for automatic connection cleanup
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            
            # Create table if not exists with proper constraints
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password_hash TEXT NOT NULL,\n                    salt TEXT NOT NULL\n                )\n            ''')
            
            # Generate unique cryptographically secure salt for this user
            salt = generate_salt()
            
            # Hash password with PBKDF2-HMAC-SHA256
            password_hash = hash_password(password, salt)
            
            # Encode to base64 for storage
            salt_b64 = base64.b64encode(salt).decode('utf-8')
            hash_b64 = base64.b64encode(password_hash).decode('utf-8')
            
            # Use parameterized query to prevent SQL injection
            cursor.execute(
                'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                (username, hash_b64, salt_b64)
            )
            
            conn.commit()
            return True
            
    except sqlite3.IntegrityError:
        # User already exists - return generic error
        return False
    except Exception as e:
        # Log error internally but return generic message to user
        print("Registration error occurred", file=__import__('sys').stderr)
        return False

def verify_user(username: str, password: str) -> bool:
    """Verify user credentials using stored salt and hash"""
    # Input validation
    if not username or not password:
        return False
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            cursor.execute(
                'SELECT password_hash, salt FROM users WHERE username = ?',
                (username,)
            )
            
            result = cursor.fetchone()
            if not result:
                return False
            
            stored_hash_b64, stored_salt_b64 = result
            
            # Decode from base64
            stored_hash = base64.b64decode(stored_hash_b64)
            stored_salt = base64.b64decode(stored_salt_b64)
            
            # Hash provided password with stored salt
            computed_hash = hash_password(password, stored_salt)
            
            # Constant-time comparison to prevent timing attacks
            return secrets.compare_digest(stored_hash, computed_hash)
            
    except Exception as e:
        # Log error internally but return generic message
        print("Login error occurred", file=__import__('sys').stderr)
        return False

if __name__ == '__main__':
    # Test case 1: Valid registration
    print(f"Test 1 - Valid registration: {register_user('user1', 'StrongP@ss123')}")
    
    # Test case 2: Valid login
    print(f"Test 2 - Valid login: {verify_user('user1', 'StrongP@ss123')}")
    
    # Test case 3: Invalid login (wrong password)
    print(f"Test 3 - Invalid password: {verify_user('user1', 'WrongPassword')}")
    
    # Test case 4: Invalid username (SQL injection attempt)
    print(f"Test 4 - SQL injection attempt: {register_user("admin' OR '1'='1", 'password123')}")
    
    # Test case 5: Weak password (too short)
    print(f"Test 5 - Weak password: {register_user('user2', 'weak')}")
