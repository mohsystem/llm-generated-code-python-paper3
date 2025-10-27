
import sqlite3
import hashlib
import secrets
import base64
import re

def hash_password(password, salt):
    """Securely hash password using SHA-256 with salt"""
    try:
        pwd_bytes = password.encode('utf-8')
        hash_obj = hashlib.sha256(salt + pwd_bytes)
        return base64.b64encode(hash_obj.digest()).decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"Error hashing password: {e}")

def generate_salt():
    """Generate cryptographically secure random salt"""
    return secrets.token_bytes(16)

def register_user(username, password, conn):
    """Securely register user with parameterized queries to prevent SQL injection"""
    # Input validation
    if not username or not username.strip():
        print("Invalid input: username cannot be empty")
        return False
    
    if not password or len(password) < 8:
        print("Invalid input: password must be at least 8 characters")
        return False
    
    # Sanitize username
    username = username.strip()
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        print("Invalid username format")
        return False
    
    try:
        # Generate salt and hash password
        salt = generate_salt()
        hashed_password = hash_password(password, salt)
        salt_string = base64.b64encode(salt).decode('utf-8')
        
        # Use parameterized query to prevent SQL injection
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, hashed_password, salt_string)
        )
        conn.commit()
        
        return cursor.rowcount > 0
    except sqlite3.IntegrityError:
        print("Username already exists")
        return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

def initialize_database(conn):
    """Create users table if it doesn't exist"""
    try:
        cursor = conn.cursor()
        cursor.execute("""\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT UNIQUE NOT NULL,\n                password_hash TEXT NOT NULL,\n                salt TEXT NOT NULL\n            )\n        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error creating table: {e}")

def main():
    # Using SQLite in-memory database for demonstration
    conn = sqlite3.connect(':memory:')
    
    try:
        initialize_database(conn)
        
        # Test cases
        print("Test Case 1: Valid registration")
        print(f"Result: {register_user('testuser1', 'SecurePass123', conn)}")
        
        print("\\nTest Case 2: Another valid registration")
        print(f"Result: {register_user('alice_99', 'MyP@ssw0rd!', conn)}")
        
        print("\\nTest Case 3: Short password (should fail)")
        print(f"Result: {register_user('testuser2', 'short', conn)}")
        
        print("\\nTest Case 4: Empty username (should fail)")
        print(f"Result: {register_user('', 'ValidPass123', conn)}")
        
        print("\\nTest Case 5: Invalid username characters (should fail)")
        print(f"Result: {register_user('test@user!', 'ValidPass123', conn)}")
        
    finally:
        conn.close()

if __name__ == "__main__":
    main()
