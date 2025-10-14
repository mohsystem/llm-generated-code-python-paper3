# Simulating a database with a dictionary
user_database = {}

def register_user(name, email, password):
    """
    Registers a new user in the database.
    :param name: The user's name.
    :param email: The user's email (must be unique).
    :param password: The user's password.
    :return: True if registration is successful, False if the email already exists.
    """
    if email in user_database:
        print(f"Registration failed: Email '{email}' already exists.")
        return False
    
    user_data = {
        'name': name,
        'password': password # In a real app, this should be hashed
    }
    user_database[email] = user_data
    print(f"Registration successful for: User{{name='{name}', email='{email}'}}")
    return True

def main():
    """ Main function with test cases """
    print("--- User Registration System ---")

    # Test Case 1: Successful registration
    print("\nTest Case 1:")
    register_user("Alice", "alice@example.com", "password123")

    # Test Case 2: Successful registration
    print("\nTest Case 2:")
    register_user("Bob", "bob@example.com", "securepass")

    # Test Case 3: Failed registration (duplicate email)
    print("\nTest Case 3:")
    register_user("Alice Smith", "alice@example.com", "anotherpass")

    # Test Case 4: Successful registration
    print("\nTest Case 4:")
    register_user("Charlie", "charlie@example.com", "charlie!@#")
    
    # Test Case 5: Successful registration
    print("\nTest Case 5:")
    register_user("Diana", "diana@example.com", "diana_pass")

    print("\n--- Current Database State ---")
    for email, user_info in user_database.items():
        print(f"Email: {email}, User: {user_info}")

if __name__ == "__main__":
    main()