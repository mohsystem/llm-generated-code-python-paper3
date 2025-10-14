import hashlib
import os
import hmac

SALT_LENGTH = 16
users_db = {}

def register_user(username, password):
    """
    Registers a new user by generating a salt, hashing the password, and storing it.
    Returns True on success, False on failure.
    """
    if not username or not password:
        print("Error: Username and password cannot be empty.")
        return False
    if username in users_db:
        print(f"Error: User '{username}' already exists.")
        return False

    salt = os.urandom(SALT_LENGTH)
    
    # Concatenate salt and password before hashing
    password_bytes = password.encode('utf-8')
    salted_password = salt + password_bytes
    
    hashed_password = hashlib.sha256(salted_password).digest()

    users_db[username] = {"salt": salt, "hashed_password": hashed_password}
    return True

def authenticate_user(username, password):
    """
    Authenticates a user by re-hashing the provided password with the stored salt.
    Returns True if credentials are valid, False otherwise.
    """
    if username not in users_db:
        # Return False for non-existent user to prevent username enumeration
        return False

    user_data = users_db[username]
    salt = user_data["salt"]
    stored_hashed_password = user_data["hashed_password"]

    # Hash the provided password with the same salt
    password_bytes = password.encode('utf-8')
    salted_password = salt + password_bytes
    input_hashed_password = hashlib.sha256(salted_password).digest()

    # Use hmac.compare_digest for constant-time comparison to prevent timing attacks
    return hmac.compare_digest(stored_hashed_password, input_hashed_password)

if __name__ == "__main__":
    print("Running 5 test cases for User Authentication...")

    # Test Case 1: Register a new user
    print("\n--- Test Case 1: Successful Registration ---")
    reg_success = register_user("alice", "Password123!")
    print(f"Registration for 'alice': {'SUCCESS' if reg_success else 'FAIL'}")

    # Test Case 2: Authenticate with correct password
    print("\n--- Test Case 2: Successful Authentication ---")
    auth_success = authenticate_user("alice", "Password123!")
    print(f"Authentication for 'alice' with correct password: {'SUCCESS' if auth_success else 'FAIL'}")

    # Test Case 3: Authenticate with incorrect password
    print("\n--- Test Case 3: Failed Authentication (Wrong Password) ---")
    auth_fail_wrong_pass = authenticate_user("alice", "WrongPassword")
    print(f"Authentication for 'alice' with wrong password: {'SUCCESS (Correctly Failed)' if not auth_fail_wrong_pass else 'FAIL'}")
    
    # Test Case 4: Authenticate a non-existent user
    print("\n--- Test Case 4: Failed Authentication (Non-Existent User) ---")
    auth_fail_non_existent = authenticate_user("bob", "Password123!")
    print(f"Authentication for non-existent 'bob': {'SUCCESS (Correctly Failed)' if not auth_fail_non_existent else 'FAIL'}")
    
    # Test Case 5: Registering an existing user
    print("\n--- Test Case 5: Failed Registration (User Exists) ---")
    reg_fail_exists = register_user("alice", "AnotherPassword")
    print(f"Re-registration for 'alice': {'SUCCESS (Correctly Failed)' if not reg_fail_exists else 'FAIL'}")

    # Bonus Test Case: Register another user with the same password
    print("\n--- Bonus Test Case: Salting Verification ---")
    register_user("charlie", "Password123!")
    alice_hash = users_db.get("alice", {}).get("hashed_password")
    charlie_hash = users_db.get("charlie", {}).get("hashed_password")
    hashes_differ = alice_hash != charlie_hash
    print(f"Alice's and Charlie's (same password) hashes are different due to salting: {'SUCCESS' if hashes_differ else 'FAIL'}")