import hashlib

# In-memory dictionary to store user credentials
user_database = {}

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    """
    Registers a new user.
    Returns True on success, False if the user already exists or input is invalid.
    """
    if not username or not password:
        print("Registration failed: Username and password cannot be empty.")
        return False
    if username in user_database:
        print(f"Registration failed: Username '{username}' already exists.")
        return False
    
    hashed_password = hash_password(password)
    user_database[username] = hashed_password
    print(f"User '{username}' registered successfully.")
    return True

def login_user(username, password):
    """
    Authenticates a user.
    Returns True if credentials are correct, False otherwise.
    """
    if not username or not password or username not in user_database:
        return False  # User not found or invalid input
    
    stored_hash = user_database[username]
    entered_hash = hash_password(password)
    return stored_hash == entered_hash

def main():
    """Main function with test cases."""
    print("--- Python User Authentication System ---")
    
    # Test Case 1: Successful registration
    register_user("alice", "password123")

    # Test Case 2: Attempt to register an existing user
    register_user("alice", "another_password")

    # Test Case 3: Successful login
    login1_success = login_user("alice", "password123")
    print(f"Login attempt for 'alice' with correct password: {'Success' if login1_success else 'Failed'}")

    # Test Case 4: Failed login (wrong password)
    login2_success = login_user("alice", "wrong_password")
    print(f"Login attempt for 'alice' with incorrect password: {'Success' if login2_success else 'Failed'}")

    # Test Case 5: Failed login (non-existent user)
    login3_success = login_user("bob", "password123")
    print(f"Login attempt for non-existent user 'bob': {'Success' if login3_success else 'Failed'}")

if __name__ == "__main__":
    main()