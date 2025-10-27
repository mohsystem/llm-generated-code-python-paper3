# Simulates a user database
user_database = {
    "admin": "password123",
    "johndoe": "secret",
    "testuser": "test"
}

def login(username, password):
    """
    Checks user credentials against the database.
    :param username: The username to check.
    :param password: The password to check.
    :return: A string indicating the result of the login attempt.
    """
    if username in user_database and user_database[username] == password:
        return "Login Successful. Redirecting to the dashboard."
    else:
        return "Invalid username or password. Redirecting to the login page."

def main():
    """ Main function to run test cases. """
    print("--- Python Login System Test Cases ---")

    # Test Case 1: Correct credentials
    print(f"Test 1 (admin, password123): {login('admin', 'password123')}")

    # Test Case 2: Correct username, incorrect password
    print(f"Test 2 (admin, wrongpass): {login('admin', 'wrongpass')}")

    # Test Case 3: Incorrect username
    print(f"Test 3 (user, password123): {login('user', 'password123')}")

    # Test Case 4: Another set of correct credentials
    print(f"Test 4 (johndoe, secret): {login('johndoe', 'secret')}")

    # Test Case 5: Non-existent user
    print(f"Test 5 (guest, guest): {login('guest', 'guest')}")

if __name__ == "__main__":
    main()