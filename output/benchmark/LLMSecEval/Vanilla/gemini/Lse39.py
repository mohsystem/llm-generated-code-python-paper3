def login(username, password):
    """
    Checks if the provided username and password are correct.
    :param username: The username to check.
    :param password: The password to check.
    :return: True if credentials are correct, False otherwise.
    """
    # Hardcoded correct credentials
    correct_username = "admin"
    correct_password = "password123"

    # Check if both username and password match
    return username == correct_username and password == correct_password

def main():
    # 5 test cases
    test_cases = [
        ("admin", "password123"),    # 1. Correct credentials
        ("admin", "wrongpassword"),  # 2. Correct username, wrong password
        ("user", "password123"),     # 3. Wrong username, correct password
        ("user", "wrongpassword"),   # 4. Both wrong
        ("", "")                     # 5. Empty credentials
    ]

    for username, password in test_cases:
        print(f"Testing with Username: '{username}', Password: '{password}'")
        if login(username, password):
            print("Login successful. Redirecting to session page.")
        else:
            print("Incorrect username or password.")
        print("--------------------")

if __name__ == "__main__":
    main()