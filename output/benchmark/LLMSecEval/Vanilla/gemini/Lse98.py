import hashlib

# Simulating a database table with a dictionary
user_database = {}

def hash_password(password):
    """
    Hashes a password using the SHA-256 algorithm.
    :param password: The plain text password.
    :return: A hex string representation of the hashed password.
    """
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()

def register_user(username, password):
    """
    Registers a new user if the username doesn't already exist.
    :param username: The username for the new account.
    :param password: The password for the new account.
    :return: True if registration is successful, False otherwise.
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
    print("--- Python Registration Test ---")
    
    # Test Case 1: Successful registration
    register_user("alice", "password123")
    
    # Test Case 2: Successful registration for another user
    register_user("bob", "securePass!@#")
    
    # Test Case 3: Attempting to register with an existing username
    register_user("alice", "anotherPassword")
    
    # Test Case 4: Successful registration with a complex username
    register_user("charlie_1990", "my-secret-pw")
    
    # Test Case 5: Successful registration
    register_user("david", "d@v1dP@$$")

    print("\n--- Current Database State ---")
    for username, hashed_pass in user_database.items():
        print(f"Username: {username}, Hashed Password: {hashed_pass}")

if __name__ == "__main__":
    main()