import hashlib
import os
import base64

# In a real application, this would be a database.
user_database = {}

SALT_BYTES = 16
HASH_ITERATIONS = 310000
HASH_ALGORITHM = 'sha256'
KEY_LENGTH = 32 # Corresponds to SHA-256 output size

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes the password using PBKDF2 with a salt."""
    if not isinstance(password, str) or not isinstance(salt, bytes):
        raise TypeError("Password must be a string and salt must be bytes.")
    
    # We encode the password to bytes before hashing.
    password_bytes = password.encode('utf-8')
    
    hashed_password = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password_bytes,
        salt,
        HASH_ITERATIONS,
        dklen=KEY_LENGTH
    )
    # Clear the intermediate password bytes from memory (best effort)
    del password_bytes
    return hashed_password

def insert_into_database(username: str, salt_b64: str, hashed_password_b64: str):
    """Simulates inserting user credentials into a database."""
    print(f"Simulating database insert for user: {username}")
    # In a real application, you would store username, salt, and hashed_password
    # in your database.
    user_database[username] = {'salt': salt_b64, 'hash': hashed_password_b64}
    print(f" -> Stored Salt: {salt_b64}")
    print(f" -> Stored Hash: {hashed_password_b64}")
    print(f"User '{username}' successfully registered.")

def register_user(username: str, password: str) -> bool:
    """Registers a new user after hashing their password."""
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
    salt = os.urandom(SALT_BYTES)

    # Hash the password
    hashed_password = hash_password(password, salt)

    # Encode salt and hash to Base64 for safe storage as strings
    salt_b64 = base64.b64encode(salt).decode('ascii')
    hashed_password_b64 = base64.b64encode(hashed_password).decode('ascii')
    
    insert_into_database(username, salt_b64, hashed_password_b64)
    return True

def main():
    """Main function with 5 test cases."""
    print("--- Running 5 Test Cases ---")

    print("\n--- Test Case 1: Valid user ---")
    register_user("alice", "Password123!")

    print("\n--- Test Case 2: Another valid user ---")
    register_user("bob", "SecurePass!@#$")

    print("\n--- Test Case 3: User with short password ---")
    register_user("charlie", "short")

    print("\n--- Test Case 4: Duplicate username ---")
    register_user("alice", "AnotherPassword456")

    print("\n--- Test Case 5: User with empty username ---")
    register_user(" ", "ValidPassword123")

    print("\n--- Test Cases Finished ---")

if __name__ == "__main__":
    main()