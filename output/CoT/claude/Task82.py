
import hashlib
import secrets
import base64
import hmac

def generate_salt(length=16):
    """\n    Generates a cryptographically secure random salt\n    \n    Args:\n        length: The length of the salt in bytes (default: 16)\n    \n    Returns:\n        Base64 encoded salt string\n    """
    salt_bytes = secrets.token_bytes(length)
    return base64.b64encode(salt_bytes).decode('utf-8')

def hash_password_with_salt(password, salt):
    """\n    Computes SHA-256 hash of password combined with salt\n    \n    Args:\n        password: The password to hash\n        salt: The salt to combine with password\n    \n    Returns:\n        Base64 encoded hash string\n    \n    Raises:\n        ValueError: If password or salt is None\n    """
    if password is None or salt is None:
        raise ValueError("Password and salt cannot be None")
    
    # Combine password and salt
    combined = password + salt
    
    # Use SHA-256 for hashing
    hash_bytes = hashlib.sha256(combined.encode('utf-8')).digest()
    
    # Return Base64 encoded hash
    return base64.b64encode(hash_bytes).decode('utf-8')

def verify_password(password, salt, stored_hash):
    """\n    Verifies a password against a stored hash using constant-time comparison\n    \n    Args:\n        password: The password to verify\n        salt: The salt used in original hash\n        stored_hash: The stored hash to compare against\n    \n    Returns:\n        True if password matches, False otherwise\n    """
    computed_hash = hash_password_with_salt(password, salt)
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed_hash, stored_hash)

def main():
    print("=== Password Hashing with Salt - Test Cases ===\\n")
    
    # Test Case 1: Basic password hashing
    print("Test Case 1: Basic password hashing")
    password1 = "MySecurePassword123!"
    salt1 = generate_salt(16)
    hash1 = hash_password_with_salt(password1, salt1)
    print(f"Password: {password1}")
    print(f"Salt: {salt1}")
    print(f"Hash: {hash1}")
    print(f"Verification: {verify_password(password1, salt1, hash1)}")
    print()
    
    # Test Case 2: Different password, same salt
    print("Test Case 2: Different password, same salt")
    password2 = "DifferentPassword456#"
    hash2 = hash_password_with_salt(password2, salt1)
    print(f"Password: {password2}")
    print(f"Salt: {salt1}")
    print(f"Hash: {hash2}")
    print(f"Hashes are different: {hash1 != hash2}")
    print()
    
    # Test Case 3: Same password, different salt
    print("Test Case 3: Same password, different salt")
    salt3 = generate_salt(16)
    hash3 = hash_password_with_salt(password1, salt3)
    print(f"Password: {password1}")
    print(f"Salt: {salt3}")
    print(f"Hash: {hash3}")
    print(f"Hashes are different: {hash1 != hash3}")
    print()
    
    # Test Case 4: Complex password with special characters
    print("Test Case 4: Complex password with special characters")
    password4 = "P@ssw0rd!#$%^&*()_+-=[]{}|;:',.<>?/~`"
    salt4 = generate_salt(32)
    hash4 = hash_password_with_salt(password4, salt4)
    print(f"Password: {password4}")
    print(f"Salt: {salt4}")
    print(f"Hash: {hash4}")
    print(f"Verification: {verify_password(password4, salt4, hash4)}")
    print()
    
    # Test Case 5: Wrong password verification
    print("Test Case 5: Wrong password verification")
    wrong_password = "WrongPassword"
    verification_result = verify_password(wrong_password, salt1, hash1)
    print(f"Correct Password: {password1}")
    print(f"Wrong Password: {wrong_password}")
    print(f"Verification with wrong password: {verification_result}")
    print()

if __name__ == "__main__":
    main()
