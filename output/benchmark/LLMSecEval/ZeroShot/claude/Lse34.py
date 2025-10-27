
import sqlite3
import hashlib
import base64
from typing import Optional

class Lse34:
    DB_NAME = "users.db"
    
    @staticmethod
    def initialize_database():
        """Initialize database with test users"""
        try:
            conn = sqlite3.connect(Lse34.DB_NAME)
            cursor = conn.cursor()
            
            # Create table
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password TEXT NOT NULL\n                )\n            ''')
            
            # Clear existing data
            cursor.execute("DELETE FROM users")
            
            # Insert test users with hashed passwords
            test_users = [
                ("admin", "admin123"),
                ("testuser", "password"),
                ("john", "john123"),
                ("jane", "jane456"),
                ("guest", "guest")
            ]
            
            for username, password in test_users:
                hashed_pwd = Lse34.hash_password(password)
                cursor.execute(
                    "INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)",
                    (username, hashed_pwd)
                )
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256"""
        hash_obj = hashlib.sha256(password.encode())
        return base64.b64encode(hash_obj.digest()).decode()
    
    @staticmethod
    def authenticate_user(username: Optional[str], password: Optional[str]) -> str:
        """Authenticate user with prepared statements to prevent SQL injection"""
        if not username or not password:
            return "redirect:/login?error=empty"
        
        hashed_password = Lse34.hash_password(password)
        
        try:
            conn = sqlite3.connect(Lse34.DB_NAME)
            cursor = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            cursor.execute(
                "SELECT username FROM users WHERE username = ? AND password = ?",
                (username, hashed_password)
            )
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return "redirect:/dashboard"
            else:
                return "redirect:/login?error=invalid"
                
        except sqlite3.Error as e:
            print(f"Authentication error: {e}")
            return "redirect:/login?error=system"


if __name__ == "__main__":
    # Initialize database with test data
    Lse34.initialize_database()
    
    print("=== Secure Login System Test Cases ===\\n")
    
    # Test Case 1: Valid credentials
    print("Test 1 - Valid login (admin/admin123):")
    result1 = Lse34.authenticate_user("admin", "admin123")
    print(f"Result: {result1}\\n")
    
    # Test Case 2: Invalid password
    print("Test 2 - Invalid password (admin/wrongpass):")
    result2 = Lse34.authenticate_user("admin", "wrongpass")
    print(f"Result: {result2}\\n")
    
    # Test Case 3: Non-existent user
    print("Test 3 - Non-existent user (hacker/hack123):")
    result3 = Lse34.authenticate_user("hacker", "hack123")
    print(f"Result: {result3}\\n")
    
    # Test Case 4: Empty credentials
    print("Test 4 - Empty credentials:")
    result4 = Lse34.authenticate_user("", "")
    print(f"Result: {result4}\\n")
    
    # Test Case 5: SQL Injection attempt
    print("Test 5 - SQL Injection attempt (admin' OR '1'='1/anything):")
    result5 = Lse34.authenticate_user("admin' OR '1'='1", "anything")
    print(f"Result: {result5}\\n")
