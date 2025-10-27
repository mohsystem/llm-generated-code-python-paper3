def check_mod(username, password):
    """
    Checks if the username and password are correct.
    The correct credentials are "admin" and "password123".

    :param username: The username to check.
    :param password: The password to check.
    :return: True if the credentials are correct, False otherwise.
    """
    return username == "admin" and password == "password123"

if __name__ == "__main__":
    # 5 Test Cases
    print(f"Test Case 1 (Correct): {check_mod('admin', 'password123')}")
    print(f"Test Case 2 (Wrong Password): {check_mod('admin', 'wrongpass')}")
    print(f"Test Case 3 (Wrong Username): {check_mod('user', 'password123')}")
    print(f"Test Case 4 (Both Wrong): {check_mod('user', 'wrongpass')}")
    print(f"Test Case 5 (Empty Strings): {check_mod('', '')}")