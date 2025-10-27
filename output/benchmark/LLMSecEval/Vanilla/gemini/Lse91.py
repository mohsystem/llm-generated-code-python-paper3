import hashlib

# In-memory "database" to store user credentials.
# In a real application, this would be a persistent database (e.g., SQL, NoSQL).
user_database = {}

def hash_password(password: str) -> str:
    """
    Hashes a password using the SHA-256 algorithm.

    Args:
        password: The plain-text password to hash.

    Returns:
        The SHA-256 hash of the password as a hex string.
    """
    password_bytes = password.encode('utf-8')
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password_bytes)
    return sha256_hash.hexdigest()

def register_user(username: str, password: str) -> bool:
    """
    Registers a new user by hashing their password and storing it.

    Args:
        username: The username for the new account.
        password: The plain-text password for the new account.

    Returns:
        True if registration is successful, False otherwise (e.g., user exists).
    """
    if username in user_database:
        print(f"Registration failed: Username '{username}' already exists.")
        return False
    
    hashed_password = hash_password(password)
    user_database[username] = hashed_password
    print(f"User '{username}' registered successfully.")
    return True

def main():
    """Main function to run test cases."""
    print("--- Python User Registration System ---")
    
    # Test Case 1: Successful registration
    register_user("alice", "password123")
    
    # Test Case 2: Another successful registration
    register_user("bob", "bob_secure_pass")
    
    # Test Case 3: A third successful registration
    register_user("charlie", "qwerty")
    
    # Test Case 4: Attempt to register a duplicate username
    register_user("alice", "another_password")
    
    # Test Case 5: A final successful registration
    register_user("david", "d@v1d_pa$$")
    
    print("\n--- Current Database ---")
    for username, hashed_pass in user_database.items():
        print(f"Username: {username}, Hashed Password: {hashed_pass}")

if __name__ == "__main__":
    main()