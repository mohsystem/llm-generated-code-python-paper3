
import sqlite3
import hashlib
import secrets
import base64
import re
from datetime import datetime

class Task46:
    DB_NAME = "users.db"
    EMAIL_PATTERN = re.compile(r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')
    
    @staticmethod
    def initialize_database():
        conn = sqlite3.connect(Task46.DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                name TEXT NOT NULL,\n                email TEXT UNIQUE NOT NULL,\n                password_hash TEXT NOT NULL,\n                salt TEXT NOT NULL,\n                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n            )\n        ''')
        conn.commit()
        conn.close()
    
    @staticmethod
    def register_user(name, email, password):
        if not Task46.validate_input(name, email, password):
            return {"success": False, "message": "Invalid input parameters"}
        
        if not Task46.validate_email(email):
            return {"success": False, "message": "Invalid email format"}
        
        if not Task46.validate_password(password):
            return {"success": False, "message": "Password must be at least 8 characters long"}
        
        try:
            salt = Task46.generate_salt()
            password_hash = Task46.hash_password(password, salt)
            
            if Task46.insert_user(name, email, password_hash, salt):
                return {"success": True, "message": "User registered successfully"}
            else:
                return {"success": False, "message": "Email already exists"}
        except Exception as e:
            return {"success": False, "message": f"Registration failed: {str(e)}"}
    
    @staticmethod
    def validate_input(name, email, password):
        return (name and name.strip() and 
                email and email.strip() and 
                password)
    
    @staticmethod
    def validate_email(email):
        return bool(Task46.EMAIL_PATTERN.match(email))
    
    @staticmethod
    def validate_password(password):
        return len(password) >= 8
    
    @staticmethod
    def generate_salt():
        salt = secrets.token_bytes(16)
        return base64.b64encode(salt).decode('utf-8')
    
    @staticmethod
    def hash_password(password, salt):
        salt_bytes = base64.b64decode(salt)
        password_hash = hashlib.sha256(salt_bytes + password.encode()).digest()
        return base64.b64encode(password_hash).decode('utf-8')
    
    @staticmethod
    def insert_user(name, email, password_hash, salt):
        try:
            conn = sqlite3.connect(Task46.DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (name, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                (name, email, password_hash, salt)
            )
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            print(f"Insert error: {e}")
            return False

def main():
    Task46.initialize_database()
    print("=== User Registration System - Test Cases ===\\n")
    
    # Test Case 1: Valid registration
    result1 = Task46.register_user("John Doe", "john.doe@example.com", "SecurePass123")
    print("Test 1 - Valid registration:")
    print(f"Result: {result1['success']} - {result1['message']}\\n")
    
    # Test Case 2: Duplicate email
    result2 = Task46.register_user("Jane Doe", "john.doe@example.com", "AnotherPass456")
    print("Test 2 - Duplicate email:")
    print(f"Result: {result2['success']} - {result2['message']}\\n")
    
    # Test Case 3: Invalid email format
    result3 = Task46.register_user("Bob Smith", "invalid-email", "Password789")
    print("Test 3 - Invalid email:")
    print(f"Result: {result3['success']} - {result3['message']}\\n")
    
    # Test Case 4: Weak password
    result4 = Task46.register_user("Alice Brown", "alice@example.com", "weak")
    print("Test 4 - Weak password:")
    print(f"Result: {result4['success']} - {result4['message']}\\n")
    
    # Test Case 5: Valid registration with different user
    result5 = Task46.register_user("Charlie Wilson", "charlie@example.com", "StrongPass999")
    print("Test 5 - Another valid registration:")
    print(f"Result: {result5['success']} - {result5['message']}")

if __name__ == "__main__":
    main()
