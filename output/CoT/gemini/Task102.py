import hashlib
import os
import binascii

# In-memory dictionary to simulate a user database.
# In a real application, this would be a connection to a database.
# The structure is: {'username': {'salt': bytes, 'hash': bytes}}
user_database = {}

# --- Hashing Configuration ---
HASH_ALGORITHM = 'sha256'
SALT_SIZE_BYTES = 16
ITERATION_COUNT = 260000 # Recommended by OWASP for PBKDF2-HMAC-SHA256

def hash_password(password, salt):
    """Hashes a password with the given salt using PBKDF2."""
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATION_COUNT
    )
    return key

def setup_initial_user(username, initial_password):
    """Helper function to create an initial user in the database."""
    if username not in user_database:
        salt = os.urandom(SALT_SIZE_BYTES)
        password_hash = hash_password(initial_password, salt)
        user_database[username] = {
            'salt': salt,
            'hash': password_hash
        }
        print(f"Initial user '{username}' created.")
    else:
        print(f"User '{username}' already exists.")


def update_user_password(username, new_password):
    """
    Updates a user's password in the simulated database.
    This function hashes the new password and stores the new hash and salt.

    Args:
        username (str): The username of the user to update.
        new_password (str): The new plain-text password.

    Returns:
        bool: True if the update was successful, False otherwise.
    """
    if not username or not new_password:
        print("Error: Username and password cannot be empty.")
        return False

    if username not in user_database:
        print(f"Error: User '{username}' not found.")
        return False
    
    try:
        # Generate a new salt for each password change for security
        new_salt = os.urandom(SALT_SIZE_BYTES)
        new_password_hash = hash_password(new_password, new_salt)

        # Update the user's record in the "database"
        user_database[username]['salt'] = new_salt
        user_database[username]['hash'] = new_password_hash

        print(f"Successfully updated password for user '{username}'.")
        return True
    except Exception as e:
        print(f"An unexpected error occurred during password hashing: {e}")
        return False

def print_db_state():
    """Prints the current state of the simulated database."""
    print("--- Database State ---")
    if not user_database:
        print("Database is empty.")
        return
    for username, data in user_database.items():
        # Use binascii to convert bytes to hex for readable printing
        salt_hex = binascii.hexlify(data['salt']).decode('ascii')
        hash_hex = binascii.hexlify(data['hash']).decode('ascii')
        print(f"  '{username}':\n    Salt: {salt_hex}\n    Hash: {hash_hex}")
    print("----------------------")


if __name__ == "__main__":
    # --- Setup: Pre-populate the database ---
    setup_initial_user("user1", "oldPassword123")
    setup_initial_user("user2", "anotherOldPwd")
    print_db_state()
    
    print("\n--- Running Test Cases ---")
    
    # Test Case 1: Update password for an existing user
    print("\n[Test Case 1]: Update password for existing user 'user1'")
    update_user_password("user1", "newStrongPassword!@#")
    print_db_state()
    
    # Test Case 2: Attempt to update password for a non-existent user
    print("\n[Test Case 2]: Attempt to update password for non-existent user 'unknownUser'")
    update_user_password("unknownUser", "somePassword")
    
    # Test Case 3: Attempt to update with an empty password
    print("\n[Test Case 3]: Attempt to update 'user2' with an empty password")
    update_user_password("user2", "")
    print_db_state()

    # Test Case 4: Update password for the second user
    print("\n[Test Case 4]: Update password for existing user 'user2'")
    update_user_password("user2", "updatedP@ssword456")
    print_db_state()

    # Test Case 5: Update password for the first user again
    print("\n[Test Case 5]: Update password for 'user1' again")
    update_user_password("user1", "evenNewerPassword$")
    print_db_state()