
import sqlite3
import hashlib
import secrets
import base64
import re

class Lse97:
    DB_NAME = "users.db"
    
    @staticmethod
    def initialize_database():
        conn = sqlite3.connect(Lse97.DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''\n            CREATE TABLE IF NOT EXISTS users (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                username TEXT UNIQUE NOT NULL,\n                password_hash TEXT NOT NULL,\n                salt TEXT NOT NULL,\n                first_name TEXT NOT NULL,\n                last_name TEXT NOT NULL,\n                email TEXT NOT NULL\n            )\n        ''')
        conn.commit()
        conn.close()
    
    @staticmethod
    def generate_salt():
        return base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
    
    @staticmethod
    def hash_password(password, salt):
        salt_bytes = base64.b64decode(salt)
        password_hash = hashlib.sha256(salt_bytes + password.encode()).digest()
        return base64.b64encode(password_hash).decode('utf-8')
    
    @staticmethod
    def register_user(username, password, first_name, last_name, email):
        if not all([username, password, first_name, last_name, email]):
            return {"success": False, "message": "All fields are required"}
        
        if not re.match(r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$', email):
            return {"success": False, "message": "Invalid email format"}
        
        Lse97.initialize_database()
        
        try:
            conn = sqlite3.connect(Lse97.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cursor.fetchone()[0] > 0:
                conn.close()
                return {"success": False, "message": "Username already exists"}
            
            salt = Lse97.generate_salt()
            password_hash = Lse97.hash_password(password, salt)
            
            cursor.execute('''\n                INSERT INTO users (username, password_hash, salt, first_name, last_name, email)\n                VALUES (?, ?, ?, ?, ?, ?)\n            ''', (username, password_hash, salt, first_name, last_name, email))
            
            conn.commit()
            conn.close()
            
            return {"success": True, "message": "Registration succeeded"}
            
        except sqlite3.Error as e:
            return {"success": False, "message": f"Database error: {str(e)}"}

def main():
    print("=== User Registration System Tests ===\\n")
    
    result1 = Lse97.register_user("john_doe", "SecurePass123!", 
                                  "John", "Doe", "john@example.com")
    print(f"Test 1: {result1['message']}")
    
    result2 = Lse97.register_user("jane_smith", "StrongP@ssw0rd", 
                                  "Jane", "Smith", "jane@example.com")
    print(f"Test 2: {result2['message']}")
    
    result3 = Lse97.register_user("john_doe", "AnotherPass456", 
                                  "John", "Different", "different@example.com")
    print(f"Test 3: {result3['message']}")
    
    result4 = Lse97.register_user("bob_wilson", "MyP@ss123", 
                                  "Bob", "Wilson", "invalid-email")
    print(f"Test 4: {result4['message']}")
    
    result5 = Lse97.register_user("alice_brown", "", 
                                  "Alice", "Brown", "alice@example.com")
    print(f"Test 5: {result5['message']}")

if __name__ == "__main__":
    main()
