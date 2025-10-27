
import secrets
import hashlib
import base64
import re
from typing import Optional

# Minimum password length for security policy (CWE-521)
MIN_PASSWORD_LENGTH = 8
# Salt size in bytes (128 bits for security)
SALT_SIZE = 16
# PBKDF2 iteration count (secure minimum as per OWASP)
PBKDF2_ITERATIONS = 210000


def generate_salt() -> bytes:
    """\n    Generates a cryptographically secure random salt.\n    Uses secrets module for CSPRNG (CWE-330, CWE-759).\n    \n    Returns:\n        bytes: Cryptographically secure random salt\n    """
    # secrets.token_bytes uses os.urandom which is cryptographically secure
    return secrets.token_bytes(SALT_SIZE)


def hash_password(password: str, salt: bytes) -> bytes:
    """\n    Hashes password using PBKDF2-HMAC-SHA256.\n    Uses high iteration count and unique salt (CWE-759, CWE-916).\n    \n    Args:\n        password: Plaintext password to hash\n        salt: Unique cryptographic salt\n        \n    Returns:\n        bytes: Hashed password\n    """
    # PBKDF2-HMAC-SHA256 with high iteration count for security
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32  # 256-bit output
    )
    return password_hash


def validate_username(username: str) -> bool:
    """\n    Validates username format to prevent injection attacks.\n    Input validation as defense in depth (CWE-20).\n    \n    Args:\n        username: Username to validate\n        \n    Returns:\n        bool: True if valid, False otherwise\n    """
    if not username or not isinstance(username, str):
        return False
    # Allow 3-50 alphanumeric characters and underscore only
    return bool(re.match(r'^[a-zA-Z0-9_]{3,50}$', username))


def validate_password(password: str) -> bool:
    """\n    Validates password meets security requirements.\n    Enforces strong password policy (CWE-521).\n    \n    Args:\n        password: Password to validate\n        \n    Returns:\n        bool: True if meets requirements, False otherwise\n    """
    if not password or not isinstance(password, str):
        return False
    
    if len(password) < MIN_PASSWORD_LENGTH:
        return False
    
    # Check for required character types
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\\[\\]{};\':"\\\\|,.<>\\/?]', password))
    
    return has_upper and has_lower and has_digit and has_special


def register_user(username: str, password: str) -> str:
    """\n    Registers a new user with secure password storage.\n    Implements secure hashing with unique salt per user.\n    \n    Args:\n        username: User's chosen username\n        password: User's chosen password\n        \n    Returns:\n        str: Base64 encoded salt+hash for database storage or error message\n    """
    # Input validation - reject invalid input early (CWE-20)
    if not validate_username(username):
        return "Error: Invalid username format"
    
    if not validate_password(password):
        return (f"Error: Password must be at least {MIN_PASSWORD_LENGTH} "
                "characters with uppercase, lowercase, digit, and special character")
    
    try:
        # Generate cryptographically secure unique salt (CWE-330, CWE-759)
        salt = generate_salt()
        
        # Hash password with PBKDF2-HMAC-SHA256 (CWE-916)
        password_hash = hash_password(password, salt)
        
        # Concatenate salt and hash for storage
        salt_and_hash = salt + password_hash
        
        # Encode to Base64 for safe text storage
        stored_value = base64.b64encode(salt_and_hash).decode('utf-8')
        
        # In production: store username and stored_value in database
        # Never log passwords or hashes (CWE-532)
        return stored_value
        
    except Exception as e:
        # Return generic error, don't expose internal details (CWE-209)
        return "Error: Registration failed"


def main():
    """Test cases demonstrating secure registration."""
    # Test case 1: Valid registration
    print("Test 1 - Valid user:")
    result1 = register_user("testUser123", "SecurePass123!")
    print("Success: Hash stored" if not result1.startswith("Error") else result1)
    
    # Test case 2: Weak password (no special character)
    print("\\nTest 2 - Weak password:")
    result2 = register_user("user456", "WeakPass123")
    print(result2)
    
    # Test case 3: Invalid username (too short)
    print("\\nTest 3 - Invalid username:")
    result3 = register_user("ab", "ValidPass123!")
    print(result3)
    
    # Test case 4: Password too short
    print("\\nTest 4 - Short password:")
    result4 = register_user("validUser", "Sh0rt!")
    print(result4)
    
    # Test case 5: Valid registration with different credentials
    print("\\nTest 5 - Another valid user:")
    result5 = register_user("anotherUser_99", "AnotherSecure99#")
    print("Success: Hash stored" if not result5.startswith("Error") else result5)


if __name__ == "__main__":
    main()
