# Before running, ensure you have the 'cryptography' library installed.
# You can install it using pip:
# pip install cryptography

import os
import secrets
from typing import Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey

# --- Constants ---
SALT_SIZE = 16  # bytes
KEY_LENGTH = 32  # bytes (256 bits)
ITERATIONS = 400_000
MIN_PASSWORD_LENGTH = 8

# In-memory storage for user credentials. In a real application,
# this would be a database.
user_database: Dict[str, Dict[str, bytes]] = {}

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))

def register_user(username: str, password: str) -> bool:
    """Registers a new user if the username is not taken and password is valid."""
    if not username or not password or len(password) < MIN_PASSWORD_LENGTH:
        print("Error: Invalid username or password does not meet policy.")
        return False
    if username in user_database:
        print(f"Error: Username '{username}' already exists.")
        return False

    salt = secrets.token_bytes(SALT_SIZE)
    hashed_password = hash_password(password, salt)

    user_database[username] = {
        'salt': salt,
        'hash': hashed_password,
    }
    return True

def authenticate_user(username: str, password: str) -> bool:
    """Authenticates a user by checking their username and password."""
    if not username or not password:
        return False
        
    user_credentials = user_database.get(username)
    if user_credentials is None:
        return False

    stored_salt = user_credentials['salt']
    stored_hash = user_credentials['hash']

    try:
        calculated_hash = hash_password(password, stored_salt)
        return secrets.compare_digest(stored_hash, calculated_hash)
    except InvalidKey:
        # This exception can be raised by kdf.verify() but not by derive(),
        # good practice to be aware of it for verification scenarios.
        return False
    except Exception as e:
        print(f"An unexpected error occurred during authentication: {e}")
        return False

def main():
    """Main function with test cases."""
    # Test Case 1: Register a new user
    print("Test Case 1: Registering user 'alice'.")
    registered = register_user("alice", "Password123!")
    print(f"Registration successful: {registered}")
    print("--------------------")

    # Test Case 2: Authenticate user with correct password
    print("Test Case 2: Authenticating 'alice' with correct password.")
    authenticated = authenticate_user("alice", "Password123!")
    print(f"Authentication successful: {authenticated}")
    print("--------------------")

    # Test Case 3: Authenticate user with incorrect password
    print("Test Case 3: Authenticating 'alice' with incorrect password.")
    authenticated = authenticate_user("alice", "WrongPassword!")
    print(f"Authentication successful: {authenticated}")
    print("--------------------")

    # Test Case 4: Authenticate a non-existent user
    print("Test Case 4: Authenticating non-existent user 'bob'.")
    authenticated = authenticate_user("bob", "SomePassword")
    print(f"Authentication successful: {authenticated}")
    print("--------------------")

    # Test Case 5: Register another user and authenticate
    print("Test Case 5: Registering and authenticating 'charlie'.")
    registered = register_user("charlie", "SecurePass!@#")
    print(f"Registration of 'charlie' successful: {registered}")
    authenticated = authenticate_user("charlie", "SecurePass!@#")
    print(f"Authentication of 'charlie' successful: {authenticated}")
    print("--------------------")

    # Test Case 6: Attempt to register with a short password
    print("Test Case 6: Attempt to register with a short password.")
    registered = register_user("david", "short")
    print(f"Registration successful: {registered}")
    print("--------------------")

    # Test Case 7: Attempt to register an existing user
    print("Test Case 7: Attempt to register 'alice' again.")
    registered = register_user("alice", "AnotherPassword")
    print(f"Registration successful: {registered}")
    print("--------------------")

if __name__ == "__main__":
    main()