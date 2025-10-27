# Simulating a user database
user_database = {
    "admin": "password123",
    "user1": "userpass",
    "john.doe": "johndoe@123"
}

def login(username, password):
    """
    Checks user credentials against the database.
    
    Args:
        username (str): The username entered by the user.
        password (str): The password entered by the user.
    
    Returns:
        str: A string indicating the redirection path.
    """
    # Check if the username exists and the password matches
    if username in user_database and user_database[username] == password:
        return "Login successful. Redirecting to dashboard page."
    else:
        return "Invalid credentials. Redirecting back to login page."

if __name__ == "__main__":
    # Test Cases
    print("--- 5 Test Cases ---")

    # Test Case 1: Correct username and password
    print(f"Test 1 (admin, password123): {login('admin', 'password123')}")

    # Test Case 2: Correct username, incorrect password
    print(f"Test 2 (admin, wrongpassword): {login('admin', 'wrongpassword')}")

    # Test Case 3: Incorrect username
    print(f"Test 3 (unknownuser, password123): {login('unknownuser', 'password123')}")
    
    # Test Case 4: Another valid user
    print(f"Test 4 (user1, userpass): {login('user1', 'userpass')}")

    # Test Case 5: Case sensitivity check (username is case-sensitive)
    print(f"Test 5 (Admin, password123): {login('Admin', 'password123')}")