
import hashlib
import secrets
import base64
import sqlite3

def hash_password(password, salt):
    """Hash password with salt using SHA-256"""
    pwd_hash = hashlib.sha256(salt + password.encode()).digest()
    return base64.b64encode(pwd_hash).decode()

def generate_salt():
    """Generate a random salt"""
    return secrets.token_bytes(16)

def register_user(username, password, conn):
    """Register a new user with hashed password"""
    if not username or not password:
        return False
    
    try:
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        salt_string = base64.b64encode(salt).decode()
        
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, hashed_password, salt_string)
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        print(f"Error registering user: {e}")
        return False

if __name__ == "__main__":
    # Create in-memory database for testing
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("""\n        CREATE TABLE users (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT UNIQUE NOT NULL,\n            password_hash TEXT NOT NULL,\n            salt TEXT NOT NULL\n        )\n    """)
    
    # Test case 1: Valid registration
    print("Test 1:", register_user("john_doe", "SecurePass123!", conn))
    
    # Test case 2: Another valid registration
    print("Test 2:", register_user("jane_smith", "MyP@ssw0rd", conn))
    
    # Test case 3: Empty username
    print("Test 3:", register_user("", "password123", conn))
    
    # Test case 4: Empty password
    print("Test 4:", register_user("user123", "", conn))
    
    # Test case 5: None values
    print("Test 5:", register_user(None, None, conn))
    
    conn.close()
