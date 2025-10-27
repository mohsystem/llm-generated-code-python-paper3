def check_mod(username, password):
    """
    Checks if the provided username and password are correct.
    For this example, the correct credentials are "admin" and "password123".

    :param username: The username to check.
    :param password: The password to check.
    :return: The string 'true' if credentials are correct, 'false' otherwise.
    """
    correct_username = "admin"
    correct_password = "password123"

    if username == correct_username and password == correct_password:
        return 'true'
    else:
        return 'false'

if __name__ == '__main__':
    # Test Case 1: Correct credentials
    print(f"Test 1 (Correct): {check_mod('admin', 'password123')}")

    # Test Case 2: Incorrect password
    print(f"Test 2 (Wrong Pass): {check_mod('admin', 'wrongpass')}")

    # Test Case 3: Incorrect username
    print(f"Test 3 (Wrong User): {check_mod('user', 'password123')}")

    # Test Case 4: Both incorrect
    print(f"Test 4 (Both Wrong): {check_mod('user', 'wrongpass')}")

    # Test Case 5: None inputs
    print(f"Test 5 (None Input): {check_mod(None, None)}")