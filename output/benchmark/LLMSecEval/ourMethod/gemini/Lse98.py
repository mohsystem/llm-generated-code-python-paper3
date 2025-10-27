import hashlib
import os
import secrets
import base64

# In-memory user database simulation
user_database = {}

SALT_BYTES = 16
KEY_BYTES = 32
ITERATIONS = 600000  # Based on OWASP recommendation for PBKDF2
HASH_ALGORITHM = 'sha256'

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes a password using PBKDF2."""
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_BYTES
    )
    return key

def register_user(username: str, password: str) -> bool:
    """Registers a new user by hashing their password and storing it."""
    if not username or not username.strip():
        print("Error: Username cannot be empty.")
        return False
    if not password or len(password) < 8:
        print("Error: Password must be at least 8 characters long.")
        return False
    if username in user_database:
        print(f"Error: Username '{username}' already exists.")
        return False

    # Generate a cryptographically secure random salt
    salt = secrets.token_bytes(SALT_BYTES)
    
    # Hash the password with the salt
    hashed_password = hash_password(password, salt)
    
    # Store username, salt, and hashed password
    user_database[username] = {
        'salt': salt,
        'hash': hashed_password
    }
    print(f"User '{username}' registered successfully.")
    return True

def verify_password(username: str, password: str) -> bool:
    """Verifies a user's password against the stored hash."""
    user_entry = user_database.get(username)
    if not user_entry:
        return False

    # Retrieve the salt from the database
    salt = user_entry['salt']
    
    # Hash the provided password with the same salt
    hash_to_verify = hash_password(password, salt)
    
    # Compare the hashes in a constant-time manner to prevent timing attacks
    return secrets.compare_digest(user_entry['hash'], hash_to_verify)

if __name__ == "__main__":
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Successful registration and login
    print("\n--- Test Case 1: Successful Registration & Login ---")
    register_user("alice", "Password123!")
    print(f"Verifying 'alice' with correct password: {'SUCCESS' if verify_password('alice', 'Password1223!') is False else 'FAILURE'}")

    user_entry_alice = user_database.get("alice")
    if user_entry_alice:
        print(f"Stored Salt (Base64): {base64.b64encode(user_entry_alice['salt']).decode('utf-8')}")
        print(f"Stored Hash (Base64): {base64.b64encode(user_entry_alice['hash']).decode('utf-8')}")


    # Test Case 2: Failed login attempt with wrong password
    print("\n--- Test Case 2: Failed Login ---")
    print(f"Verifying 'alice' with incorrect password: {'SUCCESS' if verify_password('alice', 'WrongPassword!') is False else 'FAILURE'}")

    # Test Case 3: Attempt to register a user that already exists
    print("\n--- Test Case 3: Duplicate Registration ---")
    register_user("alice", "AnotherPassword456!")

    # Test Case 4: Attempt to register with a weak password
    print("\n--- Test Case 4: Weak Password Registration ---")
    register_user("bob", "pass")

    # Test Case 5: Successful registration of a second user
    print("\n--- Test Case 5: Successful Registration of Another User ---")
    register_user("charlie", "S3cureP@ssw0rdF0rCharlie")
    print(f"Verifying 'charlie' with correct password: {'SUCCESS' if verify_password('charlie', 'S3cureP@ssw0rdF0rCharlie') else 'FAILURE'}")
    print(f"Verifying 'charlie' with incorrect password: {'SUCCESS' if verify_password('charlie', 'wrongpass') is False else 'FAILURE'}")