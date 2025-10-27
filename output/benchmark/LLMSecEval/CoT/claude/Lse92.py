
import hashlib
import secrets
import base64
import re
from typing import Tuple, Optional

class Lse92:
    SALT_LENGTH = 16
    HASH_ITERATIONS = 100000
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128

    @staticmethod
    def register_user(username: str, password: str) -> Tuple[bool, str, Optional[str], Optional[str]]:
        """\n        Register a user with username and password.\n        Returns: (success, message, hashed_password, salt)\n        """
        # Input validation
        if not username or not username.strip():
            return False, "Username cannot be empty", None, None

        if not Lse92.USERNAME_PATTERN.match(username):
            return False, "Invalid username format", None, None

        if not password or len(password) < Lse92.MIN_PASSWORD_LENGTH:
            return False, "Password too short", None, None

        if len(password) > Lse92.MAX_PASSWORD_LENGTH:
            return False, "Password too long", None, None

        try:
            # Generate salt using cryptographically secure random
            salt = secrets.token_bytes(Lse92.SALT_LENGTH)
            
            # Hash password using PBKDF2
            hashed_password = Lse92._hash_password(password, salt)
            salt_base64 = base64.b64encode(salt).decode('utf-8')
            hashed_base64 = base64.b64encode(hashed_password).decode('utf-8')

            return True, "Registration successful", hashed_base64, salt_base64
        except Exception as e:
            return False, "Registration failed", None, None

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> bytes:
        """Hash password using PBKDF2-HMAC-SHA256"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            Lse92.HASH_ITERATIONS,
            dklen=32
        )


def main():
    print("Registration Form - Test Cases\\n")

    # Test case 1: Valid registration
    success, message, hashed, salt = Lse92.register_user("john_doe", "SecurePass123!")
    print("Test 1 - Valid user:")
    print(f"Success: {success}, Message: {message}")
    if success:
        print(f"Hash: {hashed[:20]}...")

    # Test case 2: Short password
    success, message, hashed, salt = Lse92.register_user("alice", "pass")
    print("\\nTest 2 - Short password:")
    print(f"Success: {success}, Message: {message}")

    # Test case 3: Invalid username
    success, message, hashed, salt = Lse92.register_user("user@name!", "ValidPass123")
    print("\\nTest 3 - Invalid username:")
    print(f"Success: {success}, Message: {message}")

    # Test case 4: Empty username
    success, message, hashed, salt = Lse92.register_user("", "ValidPass123")
    print("\\nTest 4 - Empty username:")
    print(f"Success: {success}, Message: {message}")

    # Test case 5: Valid registration with special characters
    success, message, hashed, salt = Lse92.register_user("user_123", "MyP@ssw0rd!2024")
    print("\\nTest 5 - Valid user with special chars:")
    print(f"Success: {success}, Message: {message}")
    if success:
        print(f"Hash: {hashed[:20]}...")


if __name__ == "__main__":
    main()
