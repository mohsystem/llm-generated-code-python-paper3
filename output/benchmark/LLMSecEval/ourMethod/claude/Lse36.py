
import os
import sys
import hashlib
import secrets
import hmac
import base64
from typing import Optional
import sqlite3

# Rules#6: Use environment variables for credentials
DB_PATH = os.getenv("DB_PATH", ":memory:")

def login(username: str, password: str) -> bool:
    """\n    Login function that authenticates user credentials\n    Rules#3: Validate and sanitize all inputs\n    """
    # Rules#3: Validate inputs are not None
    if username is None or password is None:
        return False
    
    # Rules#3: Validate username length and format
    if not isinstance(username, str) or not isinstance(password, str):
        return False
    
    if len(username) > 255 or len(username) == 0:
        return False
    
    # Rules#15: Enforce password policy - minimum 12 characters
    if len(password) < 12 or len(password) > 128:
        return False
    
    # Rules#3: Sanitize username to prevent SQL injection
    if not all(c.isalnum() or c in '_@.+-' for c in username):
        return False
    
    conn = None
    try:
        # Rules#2: Use parameterized queries to prevent SQL injection
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Rules#2: Parameterized query prevents SQL injection
        query = "SELECT password_hash, salt FROM users WHERE username = ? LIMIT 1"
        cursor.execute(query, (username,))
        
        result = cursor.fetchone()
        
        if result:
            stored_hash, salt = result
            
            # Rules#11: Use unique salt for each password
            # Rules#10: Use PBKDF2-HMAC-SHA256 for key derivation
            computed_hash = hash_password(password, salt)
            
            # Rules#10: Constant-time comparison to prevent timing attacks
            if hmac.compare_digest(stored_hash, computed_hash):
                # Authentication successful - redirect to home page
                return True
        
        # Rules#7: Return generic error, don't reveal if username exists\n        return False\n        \n    except sqlite3.Error as e:\n        # Rules#7: Don't leak internal details
        print("Authentication failed", file=sys.stderr)
        return False
    finally:
        if conn:
            conn.close()


def hash_password(password: str, salt_str: str) -> str:
    """\n    Hash password using PBKDF2-HMAC-SHA256\n    Rules#9: Use PBKDF2 with at least 210,000 iterations\n    """
    try:
        salt = base64.b64decode(salt_str)
        
        # Rules#9: Use PBKDF2 with strong iteration count
        iterations = 210000
        key_length = 32  # 256 bits
        
        # Rules#10: Use vetted cryptographic library
        hash_bytes = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations,
            dklen=key_length
        )
        
        return base64.b64encode(hash_bytes).decode('utf-8')
    except Exception:
        raise RuntimeError("Hashing failed")


def generate_salt() -> str:
    """\n    Generate cryptographically secure salt\n    Rules#12: Use secure random generator\n    """
    # Rules#12: Use secrets module for cryptographically secure randomness
    salt = secrets.token_bytes(16)
    return base64.b64encode(salt).decode('utf-8')


def main():
    """Test cases"""
    print("Test Case 1 - Valid credentials:")
    print(login("user1", "ValidPassword123!"))
    
    print("\\nTest Case 2 - Invalid password:")
    print(login("user1", "WrongPassword"))
    
    print("\\nTest Case 3 - Non-existent user:")
    print(login("nonexistent", "SomePassword123!"))
    
    print("\\nTest Case 4 - None inputs:")
    print(login(None, None))
    
    print("\\nTest Case 5 - SQL injection attempt:")
    print(login("admin' OR '1'='1", "password"))


if __name__ == "__main__":
    main()
