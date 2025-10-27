
# Simulated user database
user_database = {
    "admin": "admin123",
    "user1": "password1",
    "moderator": "mod123",
    "john": "doe456",
    "alice": "wonderland"
}

def check_mod(username, password):
    """\n    Checks if the provided username and password are correct\n    :param username: The username from the form\n    :param password: The password from the form\n    :return: True if credentials are correct, False otherwise\n    """
    if username is None or password is None:
        return False
    
    if username not in user_database:
        return False
    
    return user_database[username] == password


if __name__ == "__main__":
    # Test case 1: Valid credentials
    print(f"Test 1 - Valid user (admin/admin123): {check_mod('admin', 'admin123')}")
    
    # Test case 2: Valid credentials
    print(f"Test 2 - Valid user (user1/password1): {check_mod('user1', 'password1')}")
    
    # Test case 3: Invalid password
    print(f"Test 3 - Invalid password (admin/wrong): {check_mod('admin', 'wrong')}")
    
    # Test case 4: Non-existent user
    print(f"Test 4 - Non-existent user (hacker/hack): {check_mod('hacker', 'hack')}")
    
    # Test case 5: None values
    print(f"Test 5 - None values (None/None): {check_mod(None, None)}")
