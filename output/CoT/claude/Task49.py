
import sqlite3
import hashlib
import re
from typing import Tuple, Optional

class Task49:
    DB_PATH = "users.db"
    EMAIL_PATTERN = re.compile(r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')
    NAME_PATTERN = re.compile(r'^[A-Za-z\\s]{1,100}$')
    
    @staticmethod
    def initialize_database():
        """Initialize the database with users table"""
        try:
            conn = sqlite3.connect(Task49.DB_PATH)
            cursor = conn.cursor()
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    name TEXT NOT NULL,\n                    email TEXT UNIQUE NOT NULL,\n                    password_hash TEXT NOT NULL,\n                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n                )\n            ''')
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    @staticmethod
    def validate_input(name: str, email: str, password: str) -> Tuple[bool, str]:
        """Validate user input data"""
        if not name or not email or not password:
            return False, "All fields are required"
        
        if len(name) > 100:
            return False, "Name too long"
        
        if len(email) > 255:
            return False, "Email too long"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        if not Task49.NAME_PATTERN.match(name):
            return False, "Invalid name format"
        
        if not Task49.EMAIL_PATTERN.match(email):
            return False, "Invalid email format"
        
        return True, "Valid"
    
    @staticmethod
    def create_user(name: str, email: str, password: str) -> Tuple[bool, str]:
        """Create a new user with validated and sanitized data"""
        is_valid, message = Task49.validate_input(name, email, password)
        if not is_valid:
            return False, message
        
        password_hash = Task49.hash_password(password)
        
        try:
            conn = sqlite3.connect(Task49.DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, password_hash)
            )
            
            conn.commit()
            conn.close()
            return True, "User created successfully"
            
        except sqlite3.IntegrityError:
            return False, "Email already exists"
        except sqlite3.Error as e:
            return False, f"Database error: {e}"

def main():
    Task49.initialize_database()
    
    print("=== Test Case 1: Valid user ===")
    success, message = Task49.create_user("John Doe", "john@example.com", "SecurePass123")
    print(f"Success: {success}, Message: {message}")
    
    print("\\n=== Test Case 2: Duplicate email ===")
    success, message = Task49.create_user("Jane Doe", "john@example.com", "AnotherPass456")
    print(f"Success: {success}, Message: {message}")
    
    print("\\n=== Test Case 3: Invalid email ===")
    success, message = Task49.create_user("Alice Smith", "invalid-email", "Password789")
    print(f"Success: {success}, Message: {message}")
    
    print("\\n=== Test Case 4: Short password ===")
    success, message = Task49.create_user("Bob Johnson", "bob@example.com", "short")
    print(f"Success: {success}, Message: {message}")
    
    print("\\n=== Test Case 5: Invalid name with numbers ===")
    success, message = Task49.create_user("Charlie123", "charlie@example.com", "ValidPass123")
    print(f"Success: {success}, Message: {message}")

if __name__ == "__main__":
    main()
