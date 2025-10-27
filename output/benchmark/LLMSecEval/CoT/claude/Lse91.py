
import sqlite3
import hashlib
import secrets
import base64
import re

def hash_password(password, salt):
    """Secure password hashing using SHA-256 with salt"""
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(key).decode('utf-8')

def generate_salt():
    """Generate random salt"""
    return secrets.token_bytes(16)

def is_valid_username(username):
    """Validate username (alphanumeric and underscore only, 3-20 chars)"""
    if username is None:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def is_valid_password(password):
    """Validate password (at least 8 characters)"""
    return password is not None and len(password) >= 8

def register_user(username, password):
    """Register a new user with secure password hashing"""
    # Input validation
    if not is_valid_username(username):
        print("Invalid username format")
        return False
    
    if not is_valid_password(password):
        print("Invalid password format")
        return False
    
    conn = None
    try:
        # Connect to SQLite database
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS users\n                         (id INTEGER PRIMARY KEY AUTOINCREMENT,\n                          username TEXT UNIQUE NOT NULL,\n                          password_hash TEXT NOT NULL,\n                          salt TEXT NOT NULL)''')
        
        # Generate salt and hash password
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        salt_string = base64.b64encode(salt).decode('utf-8')
        
        # Use parameterized query to prevent SQL injection
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                      (username, hashed_password, salt_string))
        
        conn.commit()
        print(f"User registered successfully: {username}")
        return True
        
    except sqlite3.IntegrityError:
        print("Username already exists")
        return False
    except Exception as e:
        print("Database error occurred")
        return False
    finally:
        if conn:
            conn.close()

def main():
    """Main function with test cases"""
    print("=== User Registration System ===\\n")
    
    # Test case 1: Valid registration
    print("Test 1: Valid registration")
    register_user("john_doe", "SecurePass123")
    
    # Test case 2: Duplicate username
    print("\\nTest 2: Duplicate username")
    register_user("john_doe", "AnotherPass456")
    
    # Test case 3: Invalid username (too short)
    print("\\nTest 3: Invalid username")
    register_user("ab", "ValidPass789")
    
    # Test case 4: Invalid password (too short)
    print("\\nTest 4: Invalid password")
    register_user("jane_doe", "short")
    
    # Test case 5: Valid registration with special requirements
    print("\\nTest 5: Another valid registration")
    register_user("alice_smith", "MySecurePassword2024")

if __name__ == "__main__":
    main()
