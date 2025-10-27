
import sqlite3
import hashlib
import secrets
import base64
from typing import Optional

class Lse34:
    DB_NAME = "users.db"
    
    @staticmethod
    def hash_password(password: str, salt: bytes) -> str:
        """Secure password hashing using PBKDF2"""
        pwdhash = hashlib.pbkdf2_hmac('sha256', 
                                      password.encode('utf-8'), 
                                      salt, 
                                      100000)
        return base64.b64encode(pwdhash).decode('utf-8')
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate cryptographically secure salt"""
        return secrets.token_bytes(32)
    
    @staticmethod
    def authenticate_user(username: str, password: str) -> str:
        """\n        Secure authentication using parameterized queries\n        Returns redirect path\n        """
        if not username or not password or not username.strip() or not password.strip():
            return "redirect:/login?error=invalid"
        
        try:
            conn = sqlite3.connect(Lse34.DB_NAME)
            cursor = conn.cursor()
            
            # Parameterized query prevents SQL injection
            cursor.execute(
                "SELECT password_hash, salt FROM users WHERE username = ?",
                (username,)
            )
            
            result = cursor.fetchone()
            
            if result:
                stored_hash, salt_str = result
                salt = base64.b64decode(salt_str)
                input_hash = Lse34.hash_password(password, salt)
                
                if stored_hash == input_hash:
                    conn.close()
                    return "redirect:/dashboard"
            
            conn.close()
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
        except Exception as e:
            print(f"Authentication error: {e}")
        
        return "redirect:/login?error=invalid"
    
    @staticmethod
    def create_user(username: str, password: str) -> bool:
        """Helper function to create users for testing"""
        try:
            conn = sqlite3.connect(Lse34.DB_NAME)
            cursor = conn.cursor()
            
            salt = Lse34.generate_salt()
            password_hash = Lse34.hash_password(password, salt)
            salt_str = base64.b64encode(salt).decode('utf-8')
            
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, password_hash, salt_str)
            )
            
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            print(f"Error creating user: {e}")
            return False
    
    @staticmethod
    def init_database():
        """Initialize database schema"""
        try:
            conn = sqlite3.connect(Lse34.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute("""\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password_hash TEXT NOT NULL,\n                    salt TEXT NOT NULL\n                )\n            """)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Database initialization error: {e}")


def main():
    Lse34.init_database()
    
    print("=== Test Cases ===")
    
    # Setup test users
    Lse34.create_user("admin", "SecurePass123!")
    Lse34.create_user("user1", "MyPassword456")
    Lse34.create_user("testuser", "Test@789")
    
    # Test 1: Valid credentials
    print("Test 1 - Valid login:", 
          Lse34.authenticate_user("admin", "SecurePass123!"))
    
    # Test 2: Invalid password
    print("Test 2 - Wrong password:", 
          Lse34.authenticate_user("admin", "WrongPass"))
    
    # Test 3: Non-existent user
    print("Test 3 - Invalid user:", 
          Lse34.authenticate_user("hacker", "password"))
    
    # Test 4: Empty credentials
    print("Test 4 - Empty input:", 
          Lse34.authenticate_user("", ""))
    
    # Test 5: SQL injection attempt (safely handled)
    print("Test 5 - SQL injection attempt:", 
          Lse34.authenticate_user("admin' OR '1'='1", "anything"))


if __name__ == "__main__":
    main()
