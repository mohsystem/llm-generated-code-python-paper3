# Before running, install the required library:
# pip install bcrypt
import bcrypt

# Simulated in-memory database
database = {}

def register_user(username: str, password: str) -> bool:
    """
    Hashes a password with a randomly generated salt using bcrypt and
    stores the username and hash in the simulated database.
    """
    if not username or not password:
        print("Error: Username and password cannot be empty.", flush=True)
        return False
    
    if username in database:
        print(f"Error: Username '{username}' already exists.", flush=True)
        return False
        
    try:
        # bcrypt requires the password to be in bytes
        password_bytes = password.encode('utf-8')
        
        # Generate a salt and hash the password. bcrypt.gensalt() creates a random salt.
        # bcrypt.hashpw combines the salt and hash into one string.
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        
        # Store the resulting hash (as a string) in the database
        database[username] = hashed_password.decode('utf-8')
        
        print(f"User '{username}' registered successfully.", flush=True)
        return True
    except Exception as e:
        print(f"An error occurred during registration: {e}", flush=True)
        return False

def main():
    """ Main function with 5 test cases """
    print("--- Python Registration Test ---")
    
    # Test Case 1: Successful registration
    register_user("alice", "Password123!")
    
    # Test Case 2: Successful registration
    register_user("bob", "SecurePass@2023")
    
    # Test Case 3: Attempt with empty username
    register_user("", "somepassword")
    
    # Test Case 4: Attempt to register a duplicate username
    register_user("alice", "AnotherPassword")
    
    # Test Case 5: Successful registration with complex password
    register_user("eve", "3v3_s3cr3t")

    print("\n--- Simulated Database Contents ---")
    for user, stored_hash in database.items():
        print(f"Username: {user}, Stored Hash: {stored_hash}")
    print("---------------------------------\n")

if __name__ == "__main__":
    main()