import hashlib
import secrets
import os

# Use a high iteration count for PBKDF2 as recommended by security standards.
ITERATIONS = 210000
KEY_LENGTH_BYTES = 32  # 256 bits
SALT_LENGTH_BYTES = 16

# In a real application, this would be a proper database.
# This dictionary simulates a user table.
user_database = {}

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes a password using PBKDF2 with HMAC-SHA256."""
    # We encode the password to bytes before hashing.
    password_bytes = password.encode('utf-8')
    
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH_BYTES
    )
    return hashed_password

def generate_salt() -> bytes:
    """Generates a cryptographically strong random salt."""
    return secrets.token_bytes(SALT_LENGTH_BYTES)

def insert_into_database(username: str, stored_password: str):
    """Simulates inserting user data into a database."""
    user_database[username] = stored_password
    print(f"User '{username}' registered successfully.")
    # For demonstration, we print the stored value. In production, never log this.
    print(f"Stored format (salt:hash): {stored_password}")
    print("----------------------------------------")

def register_user(username: str, password: str):
    """Registers a new user by hashing their password and storing the result."""
    if not username or not password:
        print("Error: Username and password cannot be empty.")
        print("----------------------------------------")
        return

    try:
        salt = generate_salt()
        hashed_password = hash_password(password, salt)

        # Store salt and hash together. A common format is salt:hash.
        # Using hex encoding for a text-safe representation.
        salt_hex = salt.hex()
        hash_hex = hashed_password.hex()
        
        stored_password = f"{salt_hex}:{hash_hex}"

        insert_into_database(username, stored_password)

    except Exception as e:
        print(f"An error occurred during registration: {e}")


def main():
    """Main function with test cases."""
    print("--- Running User Registration Test Cases ---")
    
    # Test Case 1
    register_user("alice", "Password123!")

    # Test Case 2
    register_user("bob", "S3cureP@ssw0rd")

    # Test Case 3
    register_user("charlie", "my-weak-password")
    
    # Test Case 4: Empty password
    register_user("david", "")

    # Test Case 5: Empty username
    register_user("", "anotherPassword")

if __name__ == "__main__":
    main()