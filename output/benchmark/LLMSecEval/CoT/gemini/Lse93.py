import hashlib

def register_user(username, password):
    """
    Hashes a password using SHA-256 and simulates inserting the user record.
    
    :param username: The username to be stored.
    :param password: The plaintext password to be hashed.
    :return: The hex-encoded SHA-256 hash of the password, or None on error.
    """
    if not username or not password:
        print("Error: Username and password cannot be empty.")
        return None
        
    # Create a new SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    # Update the hash object with the password, encoded to bytes
    sha256_hash.update(password.encode('utf-8'))
    
    # Get the hexadecimal representation of the hash
    hashed_password = sha256_hash.hexdigest()
    
    # Simulate inserting into the database
    print("--- User Registration ---")
    print("Simulating database insertion...")
    print(f"Username: {username}")
    print(f"Stored Hashed Password: {hashed_password}")
    print("-------------------------")
    
    return hashed_password

def main():
    """ Main function with 5 test cases """
    print("Running 5 test cases...")
    
    # Test Case 1
    register_user("alice", "Password123!")

    # Test Case 2
    register_user("bob", "my$ecr3tP@ssw0rd")

    # Test Case 3
    register_user("charlie", "admin")

    # Test Case 4
    register_user("dave", "daveslongandsecurepassword")
    
    # Test Case 5: Empty username test
    register_user("", "somepassword")


if __name__ == "__main__":
    main()