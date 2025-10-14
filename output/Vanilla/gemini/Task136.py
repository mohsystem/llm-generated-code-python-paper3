# In a real application, passwords should be hashed and stored securely.
# For this example, we use a simple dictionary with plain text for demonstration.
USER_DATABASE = {
    "admin": "password123",
    "user1": "securepass",
    "john.doe": "johndoe_pass"
}

def authenticate(username, password):
    """
    Authenticates a user based on username and password.
    Args:
        username (str): The username to check.
        password (str): The password to verify.
    Returns:
        bool: True if authentication is successful, False otherwise.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        return False
        
    stored_password = USER_DATABASE.get(username)
    return stored_password is not None and stored_password == password

# Main function with test cases
if __name__ == "__main__":
    print("--- User Authentication Test Cases ---")

    # Test Case 1: Successful login
    result1 = authenticate("admin", "password123")
    print(f"1. admin / password123 -> {'Success' if result1 else 'Failure'}")

    # Test Case 2: Wrong password
    result2 = authenticate("user1", "wrongpass")
    print(f"2. user1 / wrongpass -> {'Success' if result2 else 'Failure'}")

    # Test Case 3: Non-existent user
    result3 = authenticate("unknown_user", "password123")
    print(f"3. unknown_user / password123 -> {'Success' if result3 else 'Failure'}")

    # Test Case 4: Case-sensitive username
    result4 = authenticate("Admin", "password123")
    print(f"4. Admin / password123 -> {'Success' if result4 else 'Failure'}")

    # Test Case 5: Non-string input
    result5 = authenticate(None, "some_password")
    print(f"5. None / some_password -> {'Success' if result5 else 'Failure'}")