
import hashlib
import sqlite3
from typing import Optional

DB_PATH = "users.db"

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def initialize_database():
    """Create users table if it doesn't exist"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT UNIQUE NOT NULL,\n                password_hash TEXT NOT NULL\n            )\n        ''')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")

def register_user(username: str, password: str) -> bool:
    """Register a new user with hashed password"""
    if not username or not username.strip() or not password:
        return False
    
    hashed_password = hash_password(password)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hashed_password)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as e:
        print(f"Registration error: {e}")
        return False

if __name__ == "__main__":
    initialize_database()
    
    # Test case 1: Valid registration
    print(f"Test 1 - Valid registration: {register_user('john_doe', 'password123')}")
    
    # Test case 2: Another valid registration
    print(f"Test 2 - Valid registration: {register_user('jane_smith', 'securePass456')}")
    
    # Test case 3: Duplicate username (should fail)
    print(f"Test 3 - Duplicate username: {register_user('john_doe', 'differentPassword')}")
    
    # Test case 4: Empty username (should fail)
    print(f"Test 4 - Empty username: {register_user('', 'password789')}")
    
    # Test case 5: Empty password (should fail)
    print(f"Test 5 - Empty password: {register_user('bob_jones', '')}")
