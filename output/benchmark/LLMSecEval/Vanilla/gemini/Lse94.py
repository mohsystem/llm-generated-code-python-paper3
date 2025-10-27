import hashlib
import os

# Simulate a database (dictionary)
# { 'username': {'salt': b'...', 'hashed_password': '...'} }
database = {}

def register_user(username, password):
    """
    Generates a salt, hashes the password, and "inserts" into the database.
    :param username: The username to register.
    :param password: The plain-text password.
    :return: A dictionary containing the salt and hashed password, or None on failure.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        print("Error: Username and password must be strings.")
        return None

    try:
        # 1. Generate a random salt
        salt = os.urandom(16)  # 16 bytes is a good size for a salt

        # 2. Hash the password with the salt using SHA-256
        password_bytes = password.encode('utf-8')
        
        # Combine salt and password bytes
        salted_password = salt + password_bytes
        
        # Hash the combined value
        hashed_password = hashlib.sha256(salted_password).hexdigest()

        # 3. Store username, salt, and hashed password
        database[username] = {
            'salt': salt,
            'hashed_password': hashed_password
        }
        
        print(f"User '{username}' registered successfully.")
        print(f"  - Salt (Hex): {salt.hex()}")
        print(f"  - Hashed Password (Hex): {hashed_password}")
        print("-------------------------------------------------")
        
        return database[username]
    except Exception as e:
        print(f"An error occurred during registration: {e}")
        return None

def main():
    """Main function to run test cases."""
    print("--- Running 5 Test Cases for User Registration ---\n")
    
    # Test Case 1
    register_user("alice", "password123")

    # Test Case 2
    register_user("bob", "my$ecretP@ss")

    # Test Case 3
    register_user("charlie", "CharlieBrown")

    # Test Case 4
    register_user("dave", "davespassword")

    # Test Case 5: Registering a user with the same password as alice
    register_user("eve", "password123")
    
    print("\n--- Final Database State ---")
    for username, data in database.items():
        print(f"Username: {username}, HashedPassword: {data['hashed_password']}")

# In Python, the main class name Lse94 is not a standard convention.
# The script is executed directly. We run the main function when the script is executed.
if __name__ == "__main__":
    main()