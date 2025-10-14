
import hashlib
import secrets
from typing import Optional

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

# Simulated stored hash (in production, retrieve from secure storage)
# This represents SHA-256 hash of "AdminPass123!@#$"
STORED_HASH = bytes.fromhex(
    "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
)


def is_valid_admin_password(password: Optional[str]) -> bool:
    """\n    Validates an admin password against security requirements.\n    \n    Args:\n        password: The password to validate\n        \n    Returns:\n        True if password is valid, False otherwise\n    """
    if password is None:
        return False
    
    # Check length constraints
    if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
        return False
    
    # Check complexity requirements
    if not has_uppercase(password):
        return False
    
    if not has_lowercase(password):
        return False
    
    if not has_digit(password):
        return False
    
    if not has_special_character(password):
        return False
    
    # Verify against stored hash using constant-time comparison
    input_hash = hash_password(password)
    if input_hash is None:
        return False
    
    return constant_time_equals(input_hash, STORED_HASH)


def has_uppercase(s: str) -> bool:
    """Check if string contains at least one uppercase letter."""
    return any(c.isupper() for c in s)


def has_lowercase(s: str) -> bool:
    """Check if string contains at least one lowercase letter."""
    return any(c.islower() for c in s)


def has_digit(s: str) -> bool:
    """Check if string contains at least one digit."""
    return any(c.isdigit() for c in s)


def has_special_character(s: str) -> bool:
    """Check if string contains at least one special character."""
    special_chars = "!@#$%^&*()_+-=[]{}; ':\"|\\\\,.<>/?"
    return any(c in special_chars for c in s)


def hash_password(password: str) -> Optional[bytes]:
    """Hash the password using SHA-256."""
    try:
        return hashlib.sha256(password.encode('utf-8')).digest()
    except Exception:
        return None


def constant_time_equals(a: bytes, b: bytes) -> bool:
    """Compare two byte sequences in constant time."""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def main():
    """Test the password validation function."""
    # Test case 1: Valid password matching stored hash
    password1 = "AdminPass123!@#$"
    print(f"Test 1 - Valid admin password: {is_valid_admin_password(password1)}")
    
    # Test case 2: Password too short
    password2 = "Short1!"
    print(f"Test 2 - Too short password: {is_valid_admin_password(password2)}")
    
    # Test case 3: Missing special character
    password3 = "AdminPassword123"
    print(f"Test 3 - No special character: {is_valid_admin_password(password3)}")
    
    # Test case 4: Missing uppercase
    password4 = "adminpass123!@#"
    print(f"Test 4 - No uppercase: {is_valid_admin_password(password4)}")
    
    # Test case 5: Null password
    password5 = None
    print(f"Test 5 - Null password: {is_valid_admin_password(password5)}")


if __name__ == "__main__":
    main()
