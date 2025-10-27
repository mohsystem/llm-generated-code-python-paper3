
import os
import re
import hashlib
import secrets
import base64
import sqlite3
from typing import Optional

# Input validation patterns
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,30}$')
EMAIL_PATTERN = re.compile(r'^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$')
NAME_PATTERN = re.compile(r'^[a-zA-Z\\s]{1,50}$')
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def hash_password(password: str, salt: bytes) -> str:
    """\n    Hash password using PBKDF2-HMAC-SHA256 with unique salt.\n    Returns base64(salt):base64(hash) for storage.\n    """
    # Use PBKDF2-HMAC-SHA256 with 210000 iterations per OWASP recommendations
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        210000,
        dklen=32  # 256-bit hash
    )
    
    # Combine salt and hash for storage
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')
    
    return f"{salt_b64}:{hash_b64}"


def generate_salt() -> bytes:
    """Generate cryptographically secure random salt."""
    return secrets.token_bytes(16)  # 128-bit salt


def validate_username(username: Optional[str]) -> None:
    """Validate username format."""
    if not username or not USERNAME_PATTERN.match(username):
        raise ValueError("Invalid username format")


def validate_password(password: Optional[str]) -> None:
    """Validate password strength requirements."""
    if not password or len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters")


def validate_name(name: Optional[str]) -> None:
    """Validate name format."""
    if not name or not NAME_PATTERN.match(name):
        raise ValueError("Invalid name format")


def validate_email(email: Optional[str]) -> None:
    """Validate email format."""
    if not email or not EMAIL_PATTERN.match(email) or len(email) > 254:
        raise ValueError("Invalid email format")


def register_user(username: str, password: str, first_name: str, 
                 last_name: str, email: str, db_path: str) -> str:
    """\n    Register a new user with secure password hashing and SQL injection prevention.\n    \n    Args:\n        username: User's username (3-30 alphanumeric characters)\n        password: User's password (8-128 characters)\n        first_name: User's first name\n        last_name: User's last name\n        email: User's email address\n        db_path: Path to SQLite database\n    \n    Returns:\n        Status message indicating success or failure\n    """
    conn = None
    try:
        # Validate all inputs before processing
        validate_username(username)
        validate_password(password)
        validate_name(first_name)
        validate_name(last_name)
        validate_email(email)
        
        # Generate unique cryptographically secure salt
        salt = generate_salt()
        
        # Hash password with salt using PBKDF2
        hashed_password = hash_password(password, salt)
        
        # Clear password from memory
        password = None
        
        # Connect to database with isolation level for transactions
        conn = sqlite3.connect(db_path, isolation_level='DEFERRED')
        cursor = conn.cursor()
        
        # Check if username already exists using parameterized query
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if result and result[0] > 0:
            conn.rollback()
            return "Username already exists"
        
        # Insert new user with parameterized query to prevent SQL injection
        cursor.execute(
            "INSERT INTO users (username, password_hash, first_name, last_name, email) VALUES (?, ?, ?, ?, ?)",
            (username, hashed_password, first_name, last_name, email)
        )
        
        if cursor.rowcount > 0:
            conn.commit()
            return "Registration succeeded"
        else:
            conn.rollback()
            return "Registration failed"
            
    except ValueError as e:
        # Input validation failed - return generic error
        return "Invalid input provided"
    except sqlite3.IntegrityError as e:
        # Database constraint violation - log securely, return generic message
        print(f"Database integrity error: {str(e)}", file=__import__('sys').stderr)
        if conn:
            conn.rollback()
        return "Registration failed"
    except sqlite3.Error as e:
        # Database error - log securely, return generic message
        print(f"Database error during registration: {str(e)}", file=__import__('sys').stderr)
        if conn:
            conn.rollback()
        return "Registration failed"
    except Exception as e:
        # Unexpected error - log securely, return generic message
        print(f"Unexpected error: {str(e)}", file=__import__('sys').stderr)
        if conn:
            conn.rollback()
        return "Registration failed"
    finally:
        # Close database connection
        if conn:
            conn.close()


def main():
    """Test cases for user registration."""
    # Create test database
    db_path = ":memory:"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""\n        CREATE TABLE users (\n            id INTEGER PRIMARY KEY AUTOINCREMENT,\n            username TEXT UNIQUE NOT NULL,\n            password_hash TEXT NOT NULL,\n            first_name TEXT NOT NULL,\n            last_name TEXT NOT NULL,\n            email TEXT NOT NULL\n        )\n    """)
    conn.commit()
    conn.close()
    
    # Test case 1: Valid registration
    print("Test 1:", register_user("john_doe", "SecurePass123!", "John", "Doe", "john@example.com", db_path))
    
    # Test case 2: Duplicate username
    print("Test 2:", register_user("john_doe", "AnotherPass456!", "Jane", "Smith", "jane@example.com", db_path))
    
    # Test case 3: Valid registration with different user
    print("Test 3:", register_user("jane_smith", "StrongPassword789!", "Jane", "Smith", "jane@example.com", db_path))
    
    # Test case 4: Invalid username (special characters)
    print("Test 4:", register_user("user@invalid", "Password123!", "Test", "User", "test@example.com", db_path))
    
    # Test case 5: Invalid password (too short)
    print("Test 5:", register_user("testuser", "short", "Test", "User", "test2@example.com", db_path))


if __name__ == "__main__":
    main()
