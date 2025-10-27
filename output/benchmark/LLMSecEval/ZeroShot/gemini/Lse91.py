import os
import hashlib

# In-memory dictionary to simulate a user database.
# In a real application, use a persistent database (e.g., PostgreSQL, MySQL).
# Key: username, Value: "salt:hashed_password"
user_database = {}

def register_user(username, password):
    """
    Registers a new user by hashing their password and storing it.
    Uses PBKDF2 with SHA-256 for secure password hashing.

    Args:
        username (str): The username for the new account.
        password (str): The plain-text password for the new account.

    Returns:
        bool: True if registration is successful, False otherwise.
    """
    if not username or not password:
        print("Registration failed: Username and password cannot be empty.")
        return False

    if username in user_database:
        print(f"Registration failed: Username '{username}' already exists.")
        return False

    # Generate a cryptographically secure random salt
    salt = os.urandom(16)

    # Hash the password using PBKDF2
    # The iteration count should be as high as your system can tolerate (e.g., 260000+)
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Number of iterations
    )

    # Store the salt and hash, encoded as hex strings for storage
    stored_value = salt.hex() + ':' + hashed_password.hex()
    user_database[username] = stored_value

    print(f"User '{username}' registered successfully.")
    return True

def main():
    """Main function with 5 test cases."""
    print("--- Running 5 Test Cases for User Registration ---")

    # Test Case 1: Successful registration
    register_user("alice", "Password123!")

    # Test Case 2: Successful registration with a different user
    register_user("bob", "SecurePass@2023")

    # Test Case 3: Attempt to register a duplicate username
    register_user("alice", "AnotherPassword")

    # Test Case 4: Registration with an empty username
    register_user("", "some_password")

    # Test Case 5: Successful registration
    register_user("david", "MyP@ssw0rd")

    print("\n--- Final Simulated Database State ---")
    # Note: In a real application, NEVER print sensitive data like this.
    # This is for demonstration purposes only.
    for username, stored_value in user_database.items():
        print(f"Username: {username}, Stored Value: {stored_value}")

if __name__ == "__main__":
    main()