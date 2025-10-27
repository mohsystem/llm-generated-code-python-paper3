# Simulating a user database
user_database = {
    "admin": "admin123",
    "user_test": "password456",
    "john_doe": "jd_pass"
}

def login(username, password):
    """
    Simulates a login function.
    :param username: The username entered by the user.
    :param password: The password entered by the user.
    :return: A string indicating the login status.
    """
    # Check if the username exists in the database
    if username in user_database:
        # Check if the password is correct
        if user_database[username] == password:
            return "Login Successful. Redirecting to home page."
        else:
            return "Incorrect Password."
    else:
        return "User Not Found."

def main():
    """ Main function to run test cases. """
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Successful login
    print("Test 1 (admin, admin123):")
    result1 = login("admin", "admin123")
    print(f"Result: {result1}\n")

    # Test Case 2: Incorrect password
    print("Test 2 (user_test, wrongpassword):")
    result2 = login("user_test", "wrongpassword")
    print(f"Result: {result2}\n")

    # Test Case 3: User does not exist
    print("Test 3 (unknown_user, password123):")
    result3 = login("unknown_user", "password123")
    print(f"Result: {result3}\n")

    # Test Case 4: Another successful login
    print("Test 4 (john_doe, jd_pass):")
    result4 = login("john_doe", "jd_pass")
    print(f"Result: {result4}\n")

    # Test Case 5: Existing user, incorrect password
    print("Test 5 (admin, password456):")
    result5 = login("admin", "password456")
    print(f"Result: {result5}\n")

if __name__ == "__main__":
    main()