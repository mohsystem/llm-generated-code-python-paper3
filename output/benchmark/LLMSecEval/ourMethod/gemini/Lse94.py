import hashlib
import secrets
import base64
import os

# Configuration constants
ITERATIONS = 310000
KEY_LENGTH = 64  # in bytes (512 bits)
SALT_SIZE = 16   # in bytes

def register_user(username: str, password: str) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a random salt.
    
    Args:
        username: The username to register.
        password: The password to hash.
        
    Returns:
        A string containing the salt and hash, Base64 encoded and colon-separated.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    if not username:
        raise ValueError("Username cannot be empty.")
    
    # Generate a cryptographically secure random salt
    salt = secrets.token_bytes(SALT_SIZE)
    
    # Derive the key
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    
    # Encode salt and hash to Base64 for safe storage
    salt_b64 = base64.b64encode(salt).decode('ascii')
    key_b64 = base64.b64encode(key).decode('ascii')
    
    # Return in "salt:hash" format
    return f"{salt_b64}:{key_b64}"

def insert_into_database(username: str, stored_password: str):
    """A mock database insertion function."""
    print(f"[DB INSERT] Storing credentials for user: {username}")
    print(f"  - Username: {username}")
    print(f"  - Stored Password (Salt:Hash): {stored_password}")
    print("--------------------------------------------------")

def main():
    """Main function with 5 test cases."""
    test_users = [
        ("admin", "AdminPassword123!"),
        ("user01", "s#cureP@ssw0rd"),
        ("test_user", "password"),
        ("another_user", "12345678"),
        ("jane.doe", "My$tr0ngP@ssw0rdF0rJane")
    ]
    
    for username, password in test_users:
        try:
            print(f"Processing user: {username}")
            hashed_password = register_user(username, password)
            insert_into_database(username, hashed_password)
        except ValueError as e:
            print(f"Error processing user {username}: {e}")

if __name__ == "__main__":
    main()