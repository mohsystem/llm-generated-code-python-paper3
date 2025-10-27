import hashlib
import secrets
import os

# In a real application, this would be a database.
user_database = {}

# Use strong, modern parameters for PBKDF2.
# OWASP recommends at least 310,000 iterations for PBKDF2-HMAC-SHA256.
ITERATIONS = 310000
KEY_LENGTH = 32  # 32 bytes = 256 bits
SALT_BYTES = 16  # 16 bytes = 128 bits
HASH_ALGORITHM = 'sha256'

def register_user(username, password):
    """
    Registers a new user by hashing their password with a new salt.
    :param username: The username.
    :param password: The password.
    :return: True if registration is successful, False otherwise.
    """
    if not username or not password:
        print("Username and password cannot be empty.")
        return False

    if username in user_database:
        print(f"User '{username}' already exists.")
        return False
    
    # Generate a cryptographically secure random salt.
    # secrets.token_bytes is preferred over os.urandom for security-sensitive applications.
    salt = secrets.token_bytes(SALT_BYTES)
    
    # Hash the password with the salt.
    hashed_password = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    
    # Store the salt and hash concatenated.
    user_database[username] = salt + hashed_password
    print(f"User '{username}' registered successfully.")
    return True

def login_user(username, password):
    """
    Verifies a user's login credentials.
    :param username: The username.
    :param password: The password to verify.
    :return: True if the password is correct, False otherwise.
    """
    if not username or not password:
        return False

    stored_data = user_database.get(username)
    if not stored_data:
        print(f"Login failed: User '{username}' not found.")
        return False # User not found

    # Extract the salt and the stored hash.
    salt = stored_data[:SALT_BYTES]
    stored_hash = stored_data[SALT_BYTES:]
    
    # Hash the provided password with the retrieved salt.
    calculated_hash = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    
    # Compare the hashes in a constant-time manner to prevent timing attacks.
    is_match = secrets.compare_digest(stored_hash, calculated_hash)

    if is_match:
        print(f"Login successful for user '{username}'.")
    else:
        print(f"Login failed: Invalid password for user '{username}'.")

    return is_match

def main():
    """Main function to run test cases."""
    print("--- Running Test Cases ---")

    # Test Case 1: Successful registration
    print("\n[Test 1] Registering a new user 'alice'.")
    register_user("alice", "P@ssw0rd123!")

    # Test Case 2: Attempting to register a user that already exists
    print("\n[Test 2] Attempting to re-register 'alice'.")
    register_user("alice", "anotherpassword")

    # Test Case 3: Successful login
    print("\n[Test 3] Alice logs in with the correct password.")
    login_user("alice", "P@ssw0rd123!")

    # Test Case 4: Failed login (wrong password)
    print("\n[Test 4] Alice attempts to log in with an incorrect password.")
    login_user("alice", "wrongpassword")

    # Test Case 5: Failed login (user not found)
    print("\n[Test 5] Attempting to log in as a non-existent user 'bob'.")
    login_user("bob", "anypassword")

    print("\n--- Test Cases Finished ---")


if __name__ == "__main__":
    main()