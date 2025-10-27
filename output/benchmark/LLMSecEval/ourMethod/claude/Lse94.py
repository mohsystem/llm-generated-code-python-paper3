
import sqlite3
import hashlib
import secrets
import base64
import re

# Constants
SALT_LENGTH = 16  # 128-bit salt
DB_NAME = "users.db"

def generate_salt():
    """Generate cryptographically secure random salt using secrets module"""
    return secrets.token_bytes(SALT_LENGTH)

def hash_password(password, salt):
    """Hash password with salt using SHA-256"""
    # Encode password as UTF-8 bytes
    password_bytes = password.encode('utf-8')
    
    # Create hash with salt
    hash_obj = hashlib.sha256()
    hash_obj.update(salt)
    hash_obj.update(password_bytes)
    hashed_password = hash_obj.digest()
    
    # Combine salt and hash for storage
    combined = salt + hashed_password
    
    # Return base64 encoded string for database storage
    return base64.b64encode(combined).decode('utf-8')

def insert_user(username, password):
    """Insert user into database with parameterized query to prevent SQL injection"""
    # Validate username: 3-50 characters, alphanumeric and underscore only
    if not username or len(username) < 3 or len(username) > 50:
        print("Invalid username length", file=__import__('sys').stderr)
        return False
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        print("Invalid username format", file=__import__('sys').stderr)
        return False
    
    # Validate password strength: minimum 8 characters
    if not password or len(password) < 8:
        print("Password must be at least 8 characters", file=__import__('sys').stderr)
        return False
    
    # Generate unique salt for this user
    salt = generate_salt()
    
    # Hash password with salt
    hashed_password = hash_password(password, salt)
    
    try:
        # Use context manager for automatic connection closing
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hashed_password)
            )
            conn.commit()
            return True
            
    except sqlite3.IntegrityError:
        print("Username already exists", file=__import__('sys').stderr)
        return False
    except sqlite3.Error:
        print("Database error occurred", file=__import__('sys').stderr)
        return False

def initialize_database():
    """Create users table if it doesn't exist"""
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("""\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password_hash TEXT NOT NULL\n                )\n            """)
            conn.commit()
    except sqlite3.Error:
        print("Failed to initialize database", file=__import__('sys').stderr)

def main():
    # Initialize database
    initialize_database()
    
    # Test case 1: Valid user registration
    print(f"Test 1: {'PASS' if insert_user('alice123', 'SecurePass123!') else 'FAIL'}")
    
    # Test case 2: Valid user with different credentials
    print(f"Test 2: {'PASS' if insert_user('bob_user', 'MyP@ssw0rd2024') else 'FAIL'}")
    
    # Test case 3: Invalid username (too short)
    print(f"Test 3: {'PASS' if not insert_user('ab', 'ValidPass123') else 'FAIL'}")
    
    # Test case 4: Invalid password (too short)
    print(f"Test 4: {'PASS' if not insert_user('charlie', 'short') else 'FAIL'}")
    
    # Test case 5: Invalid username (special characters)
    print(f"Test 5: {'PASS' if not insert_user('user@name', 'ValidPass123') else 'FAIL'}")

if __name__ == "__main__":
    main()
