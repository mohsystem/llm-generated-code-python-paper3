
import psycopg2
import hashlib
import secrets
import base64
import re
import os
from typing import Optional

# Database connection parameters - load from environment variables
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_NAME = os.getenv('DB_NAME', 'testdb')
DB_USER = os.getenv('DB_USER', 'testuser')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'testpass')

# Password policy constants
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MAX_USERNAME_LENGTH = 50
PBKDF2_ITERATIONS = 210000  # OWASP recommendation
SALT_LENGTH = 16  # 128 bits


def generate_salt() -> bytes:
    """\n    Generates cryptographically secure random salt\n    Uses secrets module for CSPRNG (CWE-330, CWE-759)\n    """
    return secrets.token_bytes(SALT_LENGTH)


def hash_password(password: str, salt: bytes) -> str:
    """\n    Hashes password using PBKDF2-HMAC-SHA256 with unique salt\n    Prevents rainbow table attacks (CWE-759)\n    Uses strong KDF with high iteration count (CWE-916)\n    """
    # PBKDF2-HMAC-SHA256 with 210,000 iterations
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32  # 256-bit output
    )
    
    # Combine salt and hash for storage
    combined = salt + key
    return base64.b64encode(combined).decode('utf-8')


def is_valid_username(username: Optional[str]) -> bool:
    """\n    Validates username input to prevent injection (CWE-89)\n    Enforces length and character whitelist (CWE-20)\n    """
    if not username:
        return False
    
    # Check length constraint
    if len(username) > MAX_USERNAME_LENGTH:
        return False
    
    # Whitelist: alphanumeric, underscore, hyphen only
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))


def is_valid_password(password: Optional[str]) -> bool:
    """\n    Validates password meets security policy (CWE-521)\n    Enforces length and complexity requirements\n    """
    if not password:
        return False
    
    # Check length constraints
    if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
        return False
    
    # Check complexity requirements
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    return has_upper and has_lower and has_digit and has_special


def register_user(username: str, password: str) -> bool:
    """\n    Registers user with secure password hashing\n    Uses parameterized queries to prevent SQL injection (CWE-89)\n    """
    # Input validation (CWE-20)
    if not is_valid_username(username):
        print("Invalid username format", file=__import__('sys').stderr)
        return False
    
    if not is_valid_password(password):
        print("Password does not meet security requirements", file=__import__('sys').stderr)
        return False
    
    conn = None
    cursor = None
    
    try:
        # Generate unique salt for this password (CWE-759, CWE-330)
        salt = generate_salt()
        
        # Hash password with salt using PBKDF2 (CWE-916)
        hashed_password = hash_password(password, salt)
        
        # Establish database connection
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        cursor = conn.cursor()
        
        # Use parameterized query to prevent SQL injection (CWE-89)
        sql = "INSERT INTO users (username, password_hash) VALUES (%s, %s)"
        cursor.execute(sql, (username, hashed_password))
        
        conn.commit()
        return True
        
    except psycopg2.Error as e:
        # Generic error message to prevent information disclosure (CWE-209)
        print("Database operation failed", file=__import__('sys').stderr)
        if conn:
            conn.rollback()
        return False
    except Exception as e:
        print("Operation failed", file=__import__('sys').stderr)
        return False
    finally:
        # Ensure resources are closed (CWE-404)
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def main():
    """Test cases with secure passwords"""
    print("Test 1: Valid user")
    print(register_user("testuser1", "SecureP@ssw0rd123"))
    
    print("\\nTest 2: Valid user with special chars")
    print(register_user("john_doe", "MyP@ssw0rd!2024"))
    
    print("\\nTest 3: Invalid username (too long)")
    print(register_user("a" * 51, "ValidP@ss123"))
    
    print("\\nTest 4: Invalid password (too short)")
    print(register_user("alice", "Short1!"))
    
    print("\\nTest 5: Invalid username (SQL injection attempt)")
    print(register_user("user'; DROP TABLE users--", "SecureP@ssw0rd123"))


if __name__ == "__main__":
    main()
