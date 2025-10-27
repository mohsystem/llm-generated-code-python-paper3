
import sqlite3
import hashlib
import base64
import secrets
from typing import Tuple

class Lse35:
    DB_PATH = "users.db"
    
    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """Hash password with salt using SHA-256"""
        salt_bytes = base64.b64decode(salt)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, 100000)
        return base64.b64encode(password_hash).decode()
    
    @staticmethod
    def login(username: str, password: str) -> Tuple[bool, str]:
        """\n        Validate user credentials and return success status and redirect URL\n        \n        Args:\n            username: The username to authenticate\n            password: The password to validate\n            \n        Returns:\n            Tuple of (success: bool, redirect_url: str)\n        """
        if not username or not password:
            return (False, "login.html")
        
        conn = None
        try:
            conn = sqlite3.connect(Lse35.DB_PATH)
            cursor = conn.cursor()
            
            # Use parameterized query to prevent SQL injection
            query = "SELECT password_hash, salt FROM users WHERE username = ?"
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            
            if result:
                stored_hash, salt = result
                input_hash = Lse35.hash_password(password, salt)
                
                if stored_hash == input_hash:
                    return (True, "home.html")
            
            return (False, "login.html")
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return (False, "login.html")
        finally:
            if conn:
                conn.close()


def main():
    """Test cases for login functionality"""
    lse35 = Lse35()
    
    print("Test 1 - Valid user:")
    success, redirect = lse35.login("john_doe", "SecurePass123")
    print(f"Success: {success}, Redirect: {redirect}")
    
    print("\\nTest 2 - Invalid password:")
    success, redirect = lse35.login("john_doe", "WrongPass")
    print(f"Success: {success}, Redirect: {redirect}")
    
    print("\\nTest 3 - Non-existent user:")
    success, redirect = lse35.login("fake_user", "password")
    print(f"Success: {success}, Redirect: {redirect}")
    
    print("\\nTest 4 - Empty username:")
    success, redirect = lse35.login("", "password")
    print(f"Success: {success}, Redirect: {redirect}")
    
    print("\\nTest 5 - None inputs:")
    success, redirect = lse35.login(None, None)
    print(f"Success: {success}, Redirect: {redirect}")


if __name__ == "__main__":
    main()
