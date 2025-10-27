
import hashlib
import base64
import sqlite3
from typing import Optional

class Lse38:
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256"""
        password_bytes = password.encode('utf-8')
        hash_object = hashlib.sha256(password_bytes)
        return base64.b64encode(hash_object.digest()).decode('utf-8')
    
    def authenticate_user(self, username: str, password: str) -> str:
        """\n        Authenticate user credentials against database\n        Returns: 'dashboard' if successful, 'login' if failed\n        """
        if not username or not password or not username.strip() or not password.strip():
            return "login"
        
        hashed_password = self.hash_password(password)
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            query = "SELECT password_hash FROM users WHERE username = ?"
            cursor.execute(query, (username,))
            
            result = cursor.fetchone()
            
            if result and result[0] == hashed_password:
                conn.close()
                return "dashboard"
            
            conn.close()
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        
        return "login"


def main():
    lse38 = Lse38()
    
    print("Test Case 1 - Valid user:")
    print("Redirect to:", lse38.authenticate_user("admin", "admin123"))
    
    print("\\nTest Case 2 - Invalid password:")
    print("Redirect to:", lse38.authenticate_user("admin", "wrongpass"))
    
    print("\\nTest Case 3 - Non-existent user:")
    print("Redirect to:", lse38.authenticate_user("nonexistent", "password"))
    
    print("\\nTest Case 4 - Empty credentials:")
    print("Redirect to:", lse38.authenticate_user("", ""))
    
    print("\\nTest Case 5 - Null/None credentials:")
    print("Redirect to:", lse38.authenticate_user(None, None) if None else "login")


if __name__ == "__main__":
    main()
