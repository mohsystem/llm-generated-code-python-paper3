
import secrets
import hashlib
import base64
from typing import Tuple

# Constants for secure password hashing
ITERATIONS = 210000  # PBKDF2 iterations >= 210000 for security
KEY_LENGTH = 32  # 32 bytes = 256 bits
SALT_LENGTH = 16  # 16-byte salt


def register_user(username: str, password: str) -> str:
    """\n    Registers a user by hashing their password with a unique salt.\n    \n    Args:\n        username: The username for registration\n        password: The password to be hashed\n        \n    Returns:\n        A string containing the salt and hash, separated by ':'\n        \n    Raises:\n        ValueError: If username or password validation fails\n    """
    # Validate inputs
    if not username or not username.strip():
        raise ValueError("Username cannot be empty")
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    
    # Generate a cryptographically secure random salt (unique per user)
    # Using secrets module which is a CSPRNG
    salt = secrets.token_bytes(SALT_LENGTH)
    
    # Hash the password using PBKDF2-HMAC-SHA256
    # This provides key stretching to make brute force attacks harder
    password_bytes = password.encode('utf-8')
    hash_bytes = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    
    # Encode salt and hash as Base64 for storage
    salt_encoded = base64.b64encode(salt).decode('ascii')
    hash_encoded = base64.b64encode(hash_bytes).decode('ascii')
    
    # Return salt:hash format for storage
    return f"{salt_encoded}:{hash_encoded}"


def main():
    """Test the registration function with 5 test cases"""
    
    # Test case 1: Valid username and password
    result1 = register_user("alice", "SecurePass123!")
    print(f"User 'alice' registered. Hash: {result1[:50]}...")
    
    # Test case 2: Different user with different password
    result2 = register_user("bob", "AnotherP@ss456")
    print(f"User 'bob' registered. Hash: {result2[:50]}...")
    
    # Test case 3: Same password for different user should produce different hash
    result3 = register_user("charlie", "SecurePass123!")
    print(f"User 'charlie' registered. Hash: {result3[:50]}...")
    print("Note: Same password produces different hash due to unique salt")
    
    # Test case 4: Minimum password length
    result4 = register_user("dave", "MinPass8")
    print(f"User 'dave' registered. Hash: {result4[:50]}...")
    
    # Test case 5: Long username and password
    result5 = register_user("elizabeth_longusername", "VeryLongP@ssw0rd!WithSpecialChars")
    print(f"User 'elizabeth_longusername' registered. Hash: {result5[:50]}...")


if __name__ == "__main__":
    main()
