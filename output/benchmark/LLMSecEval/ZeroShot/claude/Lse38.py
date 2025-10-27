
import sqlite3
import hashlib
from typing import Tuple

class Lse38:
    DB_NAME = "users.db"
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def init_database():
        """Initialize database with test users"""
        conn = sqlite3.connect(Lse38.DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)")
        cursor.execute("DELETE FROM users")
        
        # Insert test users with hashed passwords
        test_users = ["admin", "user1", "user2", "user3", "user4"]
        test_passwords = ["admin123", "pass123", "password", "test123", "user123"]
        
        for username, password in zip(test_users, test_passwords):
            hashed_pass = Lse38.hash_password(password)
            cursor.execute("INSERT INTO users VALUES (?, ?)", (username, hashed_pass))
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def login(username: str, password: str) -> bool:
        """Secure login function using parameterized queries"""
        hashed_password = Lse38.hash_password(password)
        
        try:
            conn = sqlite3.connect(Lse38.DB_NAME)
            cursor = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", 
                          (username, hashed_password))
            
            result = cursor.fetchone()
            conn.close()
            
            return result is not None
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return False
    
    @staticmethod
    def authenticate(username: str, password: str) -> str:
        """Authenticate user and return redirect message"""
        if Lse38.login(username, password):
            return f"REDIRECT: Dashboard - Welcome {username}!"
        else:
            return "REDIRECT: Login Page - Invalid credentials"


if __name__ == "__main__":
    # Initialize database with test data
    Lse38.init_database()
    
    print("=== Secure Login System Test Cases ===\\n")
    
    # Test case 1: Valid admin login
    print("Test 1 - Valid admin:")
    print(Lse38.authenticate("admin", "admin123"))
    
    # Test case 2: Valid user login
    print("\\nTest 2 - Valid user1:")
    print(Lse38.authenticate("user1", "pass123"))
    
    # Test case 3: Invalid password
    print("\\nTest 3 - Invalid password:")
    print(Lse38.authenticate("admin", "wrongpass"))
    
    # Test case 4: Non-existent user
    print("\\nTest 4 - Non-existent user:")
    print(Lse38.authenticate("hacker", "hack123"))
    
    # Test case 5: SQL injection attempt (protected)
    print("\\nTest 5 - SQL injection attempt:")
    print(Lse38.authenticate("admin' OR '1'='1", "anything"))
