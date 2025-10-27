# To run this code, you need to install the bcrypt library:
# pip install bcrypt

import bcrypt
import getpass # To securely get password input if running interactively

# A simple dictionary to simulate a database.
# In a real application, this would be a database like PostgreSQL or MySQL.
user_database = {}

def register_user(username, password):
    """
    Hashes a password using bcrypt and stores the username and hashed password.
    
    :param username: The username to register.
    :param password: The plain-text password to hash and store.
    :return: True if registration is successful, False otherwise.
    """
    if not username or not password:
        print("Error: Username and password cannot be empty.")
        return False

    if username in user_database:
        print(f"Registration failed: Username '{username}' already exists.")
        return False
    
    # Encode password to bytes, as required by bcrypt
    password_bytes = password.encode('utf-8')
    
    # Generate a salt and hash the password. bcrypt handles the salt automatically.
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    
    # Store the username and the hashed password (decoded to string for storage)
    user_database[username] = hashed_password.decode('utf-8')
    
    print(f"User '{username}' registered successfully.")
    return True

def main():
    """ Main function with 5 test cases """
    print("--- Running 5 Registration Test Cases ---")

    # Test Case 1: Standard registration
    register_user("alice", "Password123!")

    # Test Case 2: Another standard registration
    register_user("bob", "my$ecretP@ss")

    # Test Case 3: Registration with a different password
    register_user("charlie", "Ch@rlieR0cks")

    # Test Case 4: Attempting to register a user that already exists
    register_user("alice", "another_password")

    # Test Case 5: Registration with a long password
    register_user("david", "ThisIsAVeryLongAndSecurePassword1234567890!@#$%^&*()")

    print("\n--- Simulated Database Contents ---")
    for username, hashed_password in user_database.items():
        print(f"Username: {username}, Hashed Password: {hashed_password}")

if __name__ == "__main__":
    main()