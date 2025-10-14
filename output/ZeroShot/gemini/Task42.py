import os
import hashlib
import hmac

# In-memory user store (dictionary)
# Format: { 'username': {'salt': b'...', 'hash': b'...'} }
user_store = {}

SALT_BYTES = 16
ITERATIONS = 100000
HASH_ALGORITHM = 'sha256'

def hash_password(password, salt):
    """Hashes a password with a salt using PBKDF2."""
    if not isinstance(password, bytes):
        password = password.encode('utf-8')
    
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password,
        salt,
        ITERATIONS
    )
    return key

def register_user(username, password, store):
    """Registers a new user, storing a salted and hashed password."""
    if not username or not password:
        print("Username and password cannot be empty.")
        return False
    if username in store:
        print(f"User '{username}' already exists.")
        return False

    salt = os.urandom(SALT_BYTES)
    hashed_pass = hash_password(password, salt)
    
    store[username] = {
        'salt': salt,
        'hash': hashed_pass
    }
    return True

def login_user(username, password, store):
    """Authenticates a user by verifying their password."""
    if username not in store:
        return False

    user_data = store[username]
    salt = user_data['salt']
    stored_hash = user_data['hash']
    
    # Hash the provided password with the stored salt
    attempted_hash = hash_password(password, salt)
    
    # Use hmac.compare_digest for constant-time comparison to prevent timing attacks
    return hmac.compare_digest(stored_hash, attempted_hash)

def main():
    """Main function to run test cases."""
    print("--- User Authentication System Test ---")

    # Test Case 1: Register a new user
    print("\nTest Case 1: Register a new user 'alice'")
    registered = register_user("alice", "Password123!", user_store)
    print(f"Registration successful: {registered}")
    
    # Test Case 2: Log in with correct credentials
    print("\nTest Case 2: Log in as 'alice' with correct password")
    login_success = login_user("alice", "Password123!", user_store)
    print(f"Login successful: {login_success}")

    # Test Case 3: Log in with incorrect credentials
    print("\nTest Case 3: Log in as 'alice' with incorrect password")
    login_fail = login_user("alice", "WrongPassword", user_store)
    print(f"Login successful: {login_fail}")

    # Test Case 4: Attempt to register an existing user
    print("\nTest Case 4: Attempt to register existing user 'alice'")
    re_registered = register_user("alice", "AnotherPassword", user_store)
    print(f"Registration successful: {re_registered}")

    # Test Case 5: Attempt to log in with a non-existent user
    print("\nTest Case 5: Attempt to log in as non-existent user 'bob'")
    non_existent_login = login_user("bob", "SomePassword", user_store)
    print(f"Login successful: {non_existent_login}")


if __name__ == "__main__":
    main()