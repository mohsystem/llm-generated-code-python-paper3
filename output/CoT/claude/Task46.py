
import sqlite3
import hashlib
import secrets
import re
from typing import Tuple

class Task46:
    DB_NAME = "users.db"
    EMAIL_PATTERN = re.compile(r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$')
    
    @staticmethod
    def initialize_database():
        """Initialize the database with users table."""
        try:
            conn = sqlite3.connect(Task46.DB_NAME)
            cursor = conn.cursor()
            cursor.execute('''\n                CREATE TABLE IF NOT EXISTS users (\n                    id INTEGER PRIMARY KEY AUTOINCREMENT,\n                    name TEXT NOT NULL,\n                    email TEXT UNIQUE NOT NULL,\n                    password_hash TEXT NOT NULL,\n                    salt TEXT NOT NULL\n                )\n            ''')
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
    
    @staticmethod
    def generate_salt() -> str:
        """Generate a random salt for password hashing."""
        return secrets.token_hex(16)
    
    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """Hash password with salt using SHA-256."""
        salted_password = (salt + password).encode('utf-8')
        return hashlib.sha256(salted_password).hexdigest()
    
    @staticmethod
    def validate_name(name: str) -> bool:
        """Validate user name."""
        return name is not None and 2 <= len(name.strip()) <= 100
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format."""
        return email is not None and Task46.EMAIL_PATTERN.match(email) is not None
    
    @staticmethod
    def validate_password(password: str) -> bool:
        """Validate password strength."""
        return password is not None and 8 <= len(password) <= 128
    
    @staticmethod
    def register_user(name: str, email: str, password: str) -> Tuple[bool, str]:
        """\n        Register a new user with validation and secure storage.\n        \n        Args:\n            name: User's full name\n            email: User's email address\n            password: User's password\n            \n        Returns:\n            Tuple of (success: bool, message: str)\n        """
        # Input validation
        if not Task46.validate_name(name):
            return False, "Invalid name. Must be 2-100 characters."
        
        if not Task46.validate_email(email):
            return False, "Invalid email format."
        
        if not Task46.validate_password(password):
            return False, "Invalid password. Must be 8-128 characters."
        
        # Generate salt and hash password
        salt = Task46.generate_salt()
        password_hash = Task46.hash_password(password, salt)
        
        # Store in database using parameterized query
        try:
            conn = sqlite3.connect(Task46.DB_NAME)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO users (name, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                (name.strip(), email.lower().strip(), password_hash, salt)
            )
            
            conn.commit()
            conn.close()
            return True, "User registered successfully."
            
        except sqlite3.IntegrityError:
            return False, "Email already registered."
        except sqlite3.Error as e:
            return False, f"Registration failed: {e}"


def main():
    """Main function with test cases."""
    Task46.initialize_database()
    
    print("=== User Registration System Test Cases ===\\n")
    
    # Test Case 1: Valid registration
    success, message = Task46.register_user("John Doe", "john.doe@example.com", "SecurePass123")
    print(f"Test 1 - Valid registration: {message}")
    
    # Test Case 2: Duplicate email
    success, message = Task46.register_user("Jane Doe", "john.doe@example.com", "AnotherPass456")
    print(f"Test 2 - Duplicate email: {message}")
    
    # Test Case 3: Invalid email format
    success, message = Task46.register_user("Bob Smith", "invalid-email", "Password789")
    print(f"Test 3 - Invalid email: {message}")
    
    # Test Case 4: Weak password
    success, message = Task46.register_user("Alice Brown", "alice@example.com", "123")
    print(f"Test 4 - Weak password: {message}")
    
    # Test Case 5: Invalid name
    success, message = Task46.register_user("A", "test@example.com", "ValidPass123")
    print(f"Test 5 - Invalid name: {message}")


if __name__ == "__main__":
    main()
