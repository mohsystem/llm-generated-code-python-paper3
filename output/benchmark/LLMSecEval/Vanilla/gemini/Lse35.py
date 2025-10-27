# This dictionary simulates a database table of users
user_database = {
    "admin": "admin123",
    "john.doe": "password123",
    "jane.doe": "securepass"
}

def login(username, password):
    """
    Simulates a login function that checks credentials against a database.
    Args:
        username: The username provided by the user.
        password: The password provided by the user.
    Returns:
        A string indicating the result of the login attempt.
    """
    # Check if the username exists and the password matches
    if username in user_database and user_database[username] == password:
        return "Login successful. Redirecting to the home page."
    else:
        return "Invalid username or password. Redirecting to the login page."

if __name__ == "__main__":
    # 5 Test Cases
    print("Test Case 1: Valid credentials for 'admin'")
    print(f"Result: {login('admin', 'admin123')}")
    print("--------------------")

    print("Test Case 2: Valid credentials for 'john.doe'")
    print(f"Result: {login('john.doe', 'password123')}")
    print("--------------------")

    print("Test Case 3: Invalid password for 'admin'")
    print(f"Result: {login('admin', 'wrongpassword')}")
    print("--------------------")

    print("Test Case 4: Non-existent username")
    print(f"Result: {login('unknown_user', 'somepassword')}")
    print("--------------------")

    print("Test Case 5: Empty credentials")
    print(f"Result: {login('', '')}")
    print("--------------------")