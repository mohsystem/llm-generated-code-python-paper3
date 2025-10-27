import hashlib
import base64
import secrets

# Using PBKDF2 with HMAC-SHA256, a secure standard for password hashing.
ALGORITHM = "sha256"
# OWASP recommends 310,000 iterations for SHA256.
ITERATIONS = 310000
# 256-bit key length for SHA-256.
KEY_LENGTH = 32
# 16-byte (128-bit) salt, as recommended.
SALT_SIZE = 16

# A simple dictionary to simulate a user database.
user_database = {}

def generate_salt() -> bytes:
    """Generates a cryptographically secure random salt."""
    return secrets.token_bytes(SALT_SIZE)

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes a password using PBKDF2."""
    key = hashlib.pbkdf2_hmac(
        ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    return key

def register_user(username: str, password: str) -> str:
    """
    Registers a new user. Generates a salt, hashes the password,
    and returns the combined string for storage.
    """
    if not username or not password:
        raise ValueError("Username and password cannot be empty")
        
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # Store as Base64(salt):Base64(hash) for portability and to avoid raw byte issues.
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    hash_b64 = base64.b64encode(hashed_password).decode('utf-8')
    
    stored_password = f"{salt_b64}:{hash_b64}"
    
    # Simulate storing in a database
    user_database[username] = stored_password
    
    return stored_password

def verify_password(username: str, provided_password: str) -> bool:
    """Verifies a user's password against the stored hash."""
    stored_password = user_database.get(username)
    if not stored_password:
        return False  # User not found

    try:
        parts = stored_password.split(':')
        if len(parts) != 2:
            return False  # Invalid format
        
        salt_b64 = parts[0]
        original_hash_b64 = parts[1]
        
        salt = base64.b64decode(salt_b64)
        original_hash = base64.b64decode(original_hash_b64)
        
        new_hash = hash_password(provided_password, salt)
        
        # Use a constant-time comparison to prevent timing attacks.
        return secrets.compare_digest(original_hash, new_hash)
    except (ValueError, TypeError, base64.binascii.Error):
        # Handle potential errors during decoding or processing gracefully.
        return False

def main():
    """Main function with test cases."""
    print("--- User Registration and Verification Simulation ---")

    test_cases = [
        ("alice", "Password123!"),
        ("bob", "my$ecretP@ss"),
        ("charlie", "aVeryLongAndComplexPassword-12345"),
        ("dave", "short"),
        ("eve", "another_password")
    ]

    for username, password in test_cases:
        print(f"\n--- Testing for user: {username} ---")

        # 1. Registration
        stored_password = register_user(username, password)
        print(f"Registering user '{username}'.")
        print(f"Stored format (Base64(salt):Base64(hash)): {stored_password}")

        # 2. Verification
        print("Verifying with correct password...")
        is_correct = verify_password(username, password)
        print(f"Verification successful: {is_correct}")

        print("Verifying with incorrect password ('wrongpassword')...")
        is_incorrect = verify_password(username, "wrongpassword")
        print(f"Verification successful: {is_incorrect}")


if __name__ == "__main__":
    main()