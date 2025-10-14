
import hashlib
import os
import base64
import sqlite3

def generate_salt():
    """Generate a random salt"""
    return base64.b64encode(os.urandom(16)).decode('utf-8')

def hash_password(password, salt):
    """Hash password with salt using SHA-256"""
    salt_bytes = base64.b64decode(salt)
    password_bytes = password.encode('utf-8')
    hasher = hashlib.sha256()
    hasher.update(salt_bytes + password_bytes)
    return base64.b64encode(hasher.digest()).decode('utf-8')

def update_user_password(username, new_password, conn):
    """Update user password in database"""
    if not username or not username.strip() or not new_password or not new_password.strip():
        return False
    
    salt = generate_salt()
    hashed_password = hash_password(new_password, salt)
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
            (hashed_password, salt, username)
        )
        conn.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        print(f"Error updating password: {e}")
        return False

if __name__ == "__main__":
    # Create in-memory database for testing
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # Create test table
    cursor.execute('''\n        CREATE TABLE users (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT UNIQUE NOT NULL,\n            password_hash TEXT,\n            salt TEXT\n        )\n    ''')
    
    # Insert test users
    test_users = ["user1", "user2", "user3", "user4", "user5"]
    for user in test_users:
        cursor.execute("INSERT INTO users (username) VALUES (?)", (user,))
    conn.commit()
    
    # Test case 1: Valid username and password
    print("Test 1:", update_user_password("user1", "SecurePass123!", conn))
    
    # Test case 2: Another valid update
    print("Test 2:", update_user_password("user2", "MyP@ssw0rd", conn))
    
    # Test case 3: Non-existent user
    print("Test 3:", update_user_password("nonexistent", "password", conn))
    
    # Test case 4: Empty password
    print("Test 4:", update_user_password("user3", "", conn))
    
    # Test case 5: None username
    print("Test 5:", update_user_password(None, "password", conn))
    
    conn.close()
