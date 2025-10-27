# In-memory dictionary to simulate a user database
DATABASE = {
    "admin": "password123",
    "user": "userpass",
    "testuser": "test"
}

def login(username, password):
    """
    Checks user credentials against the database.
    
    Args:
        username (str): The username to check.
        password (str): The password to check.
    
    Returns:
        str: "success" on match, "cant_login" on mismatch, "internal_server_error" on unexpected issues.
    """
    try:
        # Check for non-string types to simulate an internal error
        if not isinstance(username, str) or not isinstance(password, str):
            raise TypeError("Username and password must be strings.")

        # Check if username exists and password matches
        if username in DATABASE and DATABASE[username] == password:
            return "success"
        else:
            return "cant_login"
    except Exception:
        # Catch any unexpected exceptions
        return "internal_server_error"

if __name__ == "__main__":
    # Test Case 1: Correct username and password
    print(f"Test 1: login('admin', 'password123') -> {login('admin', 'password123')}")

    # Test Case 2: Correct username, incorrect password
    print(f"Test 2: login('user', 'wrongpassword') -> {login('user', 'wrongpassword')}")

    # Test Case 3: Incorrect username
    print(f"Test 3: login('unknown', 'userpass') -> {login('unknown', 'userpass')}")

    # Test Case 4: Empty credentials
    print(f"Test 4: login('', '') -> {login('', '')}")

    # Test Case 5: Another correct username and password
    print(f"Test 5: login('testuser', 'test') -> {login('testuser', 'test')}")