
import secrets
import hashlib
from typing import Tuple
import base64

SALT_LENGTH = 16
ITERATIONS = 210000
KEY_LENGTH = 32

def hash_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """\n    Compute hash of password combined with salt using PBKDF2-HMAC-SHA256.\n    \n    Args:\n        password: The password to hash (must not be empty)\n        salt: Optional 16-byte salt. If not provided, a random salt is generated.\n    \n    Returns:\n        Tuple of (salt, hash) both as bytes\n    \n    Raises:\n        ValueError: If password is empty or salt has incorrect length\n    """
    if not password:
        raise ValueError("Password cannot be empty")
    
    if salt is None:
        salt = secrets.token_bytes(SALT_LENGTH)
    elif len(salt) != SALT_LENGTH:
        raise ValueError(f"Salt must be exactly {SALT_LENGTH} bytes")
    
    password_bytes = password.encode('utf-8')
    
    hash_value = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    
    return (salt, hash_value)


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    """\n    Verify a password against a stored salt and hash.\n    \n    Args:\n        password: The password to verify\n        salt: The salt used during hashing\n        expected_hash: The expected hash value\n    \n    Returns:\n        True if password matches, False otherwise\n    """
    if not password or salt is None or expected_hash is None:
        return False
    
    try:
        _, computed_hash = hash_password(password, salt)
        return constant_time_equals(computed_hash, expected_hash)
    except Exception:
        return False


def constant_time_equals(a: bytes, b: bytes) -> bool:
    """Compare two byte sequences in constant time."""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def main():
    print("Test Case 1: Hash password with auto-generated salt")
    password1 = "SecurePassword123!"
    salt1, hash1 = hash_password(password1)
    print(f"Salt (Base64): {base64.b64encode(salt1).decode('ascii')}")
    print(f"Hash (Base64): {base64.b64encode(hash1).decode('ascii')}")
    print()
    
    print("Test Case 2: Hash password with provided salt")
    password2 = "MyPassword456"
    salt2 = secrets.token_bytes(SALT_LENGTH)
    salt2_out, hash2 = hash_password(password2, salt2)
    print(f"Salt (Base64): {base64.b64encode(salt2_out).decode('ascii')}")
    print(f"Hash (Base64): {base64.b64encode(hash2).decode('ascii')}")
    print()
    
    print("Test Case 3: Verify correct password")
    password3 = "TestPassword789"
    salt3, hash3 = hash_password(password3)
    verified3 = verify_password(password3, salt3, hash3)
    print(f"Verification result: {verified3}")
    print()
    
    print("Test Case 4: Verify incorrect password")
    wrong_password = "WrongPassword"
    verified4 = verify_password(wrong_password, salt3, hash3)
    print(f"Verification result: {verified4}")
    print()
    
    print("Test Case 5: Same password, different salts produce different hashes")
    password5 = "SamePassword"
    salt5a, hash5a = hash_password(password5)
    salt5b, hash5b = hash_password(password5)
    hashes_equal = hash5a == hash5b
    print(f"Hashes equal: {hashes_equal} (should be False)")
    print(f"Hash 1 (Base64): {base64.b64encode(hash5a).decode('ascii')}")
    print(f"Hash 2 (Base64): {base64.b64encode(hash5b).decode('ascii')}")


if __name__ == "__main__":
    main()
