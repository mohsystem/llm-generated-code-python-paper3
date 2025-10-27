
import sqlite3
import hashlib
import secrets
import re
from typing import Tuple

class Lse98:
    DB_NAME = "users.db"
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
    MIN_PASSWORD_LENGTH = 8
    
    @staticmethod
    def initialize_database():
        try:
            conn = sqlite3.connect(Lse98.DB_NAME)
            cursor = conn.cursor()
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    username TEXT UNIQUE NOT NULL,\n                    password_hash TEXT NOT NULL,\n                    salt TEXT NOT NULL,\n                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n                )\n            ''')
            conn.commit()
            conn.close()
        except sqlite3.Error:
            print("Database initialization failed")
    
    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        salt_bytes = bytes.fromhex(salt)
        password_bytes = password.encode('utf-8')
        hashed = hashlib.pbkdf2_hmac('sha256', password_bytes, salt_bytes, 100000)
        return hashed.hex()
    
    @staticmethod
    def generate_salt() -> str:
        return secrets.token_hex(16)
    
    @staticmethod
    def validate_username(username: str) -> bool:
        return username is not None and Lse98.USERNAME_PATTERN.match(username) is not None
    
    @staticmethod
    def validate_password(password: str) -> bool:
        return password is not None and len(password) >= Lse98.MIN_PASSWORD_LENGTH
    
    @staticmethod
    def register_user(username: str, password: str) -> Tuple[bool, str]:
        if not Lse98.validate_username(username):
            return False, "Invalid username format"
        
        if not Lse98.validate_password(password):
            return False, f"Password must be at least {Lse98.MIN_PASSWORD_LENGTH} characters"
        
        try:
            salt = Lse98.generate_salt()
            hashed_password = Lse98.hash_password(password, salt)
            
            conn = sqlite3.connect(Lse98.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                (username, hashed_password, salt)
            )
            
            conn.commit()
            conn.close()
            
            return True, "Registration successful"
            
        except sqlite3.IntegrityError:
            return False, "Username already exists"
        except sqlite3.Error:
            return False, "Registration failed"
        except Exception:
            return False, "System error occurred"


def main():
    Lse98.initialize_database()
    
    print("=== User Registration Test Cases ===\\n")
    
    # Test Case 1: Valid registration
    success, message = Lse98.register_user("john_doe", "SecurePass123")
    print(f"Test 1 - Valid registration: {message}")
    
    # Test Case 2: Duplicate username
    success, message = Lse98.register_user("john_doe", "AnotherPass456")
    print(f"Test 2 - Duplicate username: {message}")
    
    # Test Case 3: Invalid username (too short)
    success, message = Lse98.register_user("ab", "ValidPassword1")
    print(f"Test 3 - Invalid username: {message}")
    
    # Test Case 4: Weak password
    success, message = Lse98.register_user("jane_doe", "short")
    print(f"Test 4 - Weak password: {message}")
    
    # Test Case 5: Valid registration with special characters
    success, message = Lse98.register_user("alice_smith", "Str0ng!P@ssw0rd")
    print(f"Test 5 - Valid with special chars: {message}")


if __name__ == "__main__":
    main()
