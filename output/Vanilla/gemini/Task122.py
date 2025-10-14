# A simple in-memory dictionary to store user data.
# In a real application, this would be a database.
user_database = {}

def sign_up(username, password):
    """
    Signs up a new user by storing their username and password.
    NOTE: In a real-world application, passwords should NEVER be stored in plaintext.
    They should be securely hashed.
    
    :param username: The username to register.
    :param password: The password for the new user.
    :return: True if registration is successful, False if the username already exists.
    """
    if not username:
        print(f"Signup failed: Username cannot be empty.")
        return False
        
    if username in user_database:
        print(f"Signup failed: Username '{username}' already exists.")
        return False
    
    user_database[username] = password
    print(f"Signup successful: User '{username}' created.")
    return True

def main():
    """Main function with test cases."""
    print("--- Python Test Cases ---")

    # Test Case 1: Successful signup for a new user
    sign_up("alice", "password123")

    # Test Case 2: Successful signup for another new user
    sign_up("bob", "securePass_456")

    # Test Case 3: Failed signup with an existing username
    sign_up("alice", "anotherPassword")

    # Test Case 4: Successful signup with a user whose name is a number
    sign_up("user789", "mySecret")

    # Test Case 5: Successful signup with an empty password (for demonstration)
    sign_up("charlie", "")
    
    # Print final state of the database
    print(f"\nCurrent user database: {user_database}")


if __name__ == "__main__":
    main()