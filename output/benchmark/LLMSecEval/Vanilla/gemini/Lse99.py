import hashlib

# Simulating a database with a dictionary
database = {}

def hash_password(password: str) -> str:
    """
    Hashes a password using the SHA-256 algorithm.
    :param password: The plain text password.
    :return: A hex string representation of the hashed password.
    """
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def register_user(username: str, password: str) -> bool:
    """
    "Inserts" a new user into the simulated database.
    :param username: The username for the new user.
    :param password: The password for the new user.
    :return: True if the user was successfully registered, False otherwise.
    """
    if not username or not password:
        print("Error: Username and password cannot be empty.")
        return False
    if username in database:
        print(f"Error: Username '{username}' already exists.")
        return False
    
    hashed_password = hash_password(password)
    database[username] = hashed_password
    print(f"User '{username}' registered successfully.")
    return True

def main():
    """Main function to run test cases."""
    print("--- Running 5 User Registration Test Cases ---")
    
    # Test Case 1
    register_user("alice", "password123")
    
    # Test Case 2
    register_user("bob", "my$ecretP@ss")
    
    # Test Case 3
    register_user("charlie", "Charlie'sPassword!")
    
    # Test Case 4
    register_user("david", "d@v1d_R0ck$")
    
    # Test Case 5
    register_user("eve", "spyware")
    
    print("\n--- Final Database State ---")
    for username, hashed_pwd in database.items():
        print(f"Username: {username}, Hashed Password: {hashed_pwd}")

if __name__ == "__main__":
    main()