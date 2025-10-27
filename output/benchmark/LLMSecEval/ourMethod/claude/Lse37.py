
import os
import sys
import hashlib
import secrets
import base64
import sqlite3
from typing import Optional

# Constants for PBKDF2 (Rules#6, #7, #8)
ITERATIONS = 210000
KEY_LENGTH = 32
SALT_LENGTH = 16

def generate_salt() -> bytes:
    """Generates cryptographically secure random salt (Rules#8, #9)"""
    return secrets.token_bytes(SALT_LENGTH)

def hash_password(password: str, salt: bytes) -> str:
    """Hashes password using PBKDF2-HMAC-SHA256 (Rules#1, #6, #7, #8)"""
    if not isinstance(password, str) or not isinstance(salt, bytes):
        raise ValueError("Invalid input types")
    
    # Use PBKDF2-HMAC-SHA256 with sufficient iterations (Rules#6, #7)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS, dklen=KEY_LENGTH)
    return base64.b64encode(key).decode('utf-8')

def validate_input(input_str: str) -> bool:
    """Validates input to prevent injection attacks (Rules#1, #13)"""
    if not input_str or len(input_str) > 255:
        return False
    # Allow only alphanumeric and safe characters
    return all(c.isalnum() or c in ('_', '@', '.', '-') for c in input_str)

def authenticate_user(username: str, password: str) -> str:
    """\n    Authenticates user with parameterized queries to prevent SQL injection.\n    Returns: 'success', 'cant_login', or 'internal_server_error'\n    (Rules#1, #2, #3, #4)\n    """
    # Input validation (Rules#1, #13)
    if not validate_input(username) or not password:
        return "cant_login"
    
    # Load database path from environment variable (Rules#3, #4)
    db_path = os.getenv("DB_PATH", "users.db")
    
    conn = None
    try:
        # Connect to database with secure settings
        conn = sqlite3.connect(db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Parameterized query prevents SQL injection (Rules#1, #2)
        query = "SELECT password_hash, salt FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        
        result = cursor.fetchone()
        
        if result:
            stored_hash = result['password_hash']
            salt = base64.b64decode(result['salt'])
            
            # Hash provided password with stored salt (Rules#6, #7, #8)
            computed_hash = hash_password(password, salt)
            
            # Constant-time comparison to prevent timing attacks (Rules#6)
            if secrets.compare_digest(stored_hash, computed_hash):
                return "success"
            else:
                return "cant_login"
        else:
            return "cant_login"
            
    except sqlite3.Error as e:
        # Generic error message, no details leaked (Rules#1)
        print("Database error occurred", file=sys.stderr)
        return "internal_server_error"
    except Exception as e:
        # Handle other exceptions (Rules#17)
        print("Authentication error occurred", file=sys.stderr)
        return "internal_server_error"
    finally:
        # Ensure connection is closed (Rules#17)
        if conn:
            conn.close()

def main():
    """Test cases"""
    print("Test 1 - Valid user:", authenticate_user("validuser", "ValidPass123!"))
    print("Test 2 - Invalid password:", authenticate_user("validuser", "wrongpass"))
    print("Test 3 - Invalid username:", authenticate_user("invaliduser", "password"))
    print("Test 4 - SQL injection attempt:", authenticate_user("admin' OR '1'='1", "pass"))
    print("Test 5 - Empty credentials:", authenticate_user("", ""))

if __name__ == "__main__":
    main()
