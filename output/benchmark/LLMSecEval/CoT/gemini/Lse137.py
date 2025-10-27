# In a real application, this data would come from a secure database.
# Passwords should be securely hashed (e.g., using bcrypt), not stored in plain text.
USER_DATABASE = {
    "admin": {
        "password": "pass123",  # NOTE: In a real app, this would be a hash.
        "session": "adminsession123",
        "role": "moderator"
    },
    "user": {
        "password": "password",
        "session": "usersession456",
        "role": "user"
    }
}

def auth_mod(username, password, session):
    """
    Authenticates a user and checks if they have the 'moderator' role.

    SECURITY NOTE: In a real-world scenario:
    1. Passwords must be compared using a secure hash comparison function 
       (e.g., hmac.compare_digest) to prevent timing attacks.
    2. This function should consult a database or a secure authentication service.
    3. Session tokens should be long, random, and managed securely.
    
    :param username: The user's name.
    :param password: The user's plain-text password.
    :param session:  The user's session token.
    :return: True if the user is authenticated and is a moderator, False otherwise.
    """
    if not all([username, password, session]):
        return False

    user_data = USER_DATABASE.get(username)
    if user_data:
        # NOTE: Plain text password comparison is insecure.
        is_password_correct = user_data["password"] == password
        is_session_correct = user_data["session"] == session
        is_moderator = user_data["role"] == "moderator"
        
        return is_password_correct and is_session_correct and is_moderator
        
    return False

def check_mod(username, password, session):
    """
    Checks if a user is a moderator based on parameters.

    SECURITY NOTE: Getting credentials from a URL is extremely insecure (CWE-598).
    Sensitive data like passwords and session tokens should be sent in the body
    of a POST request over HTTPS.

    :param username: The user's name.
    :param password: The user's plain-text password.
    :param session:  The user's session token.
    :return: True if the user is a moderator, False otherwise.
    """
    return auth_mod(username, password, session)

def main():
    """ Main function with test cases """
    print("--- Running Test Cases ---")

    # Test Case 1: Valid moderator credentials
    test1 = check_mod("admin", "pass123", "adminsession123")
    print(f"Test Case 1 (Valid Moderator): {'Passed' if test1 else 'Failed'}")

    # Test Case 2: Valid user but not a moderator
    test2 = check_mod("user", "password", "usersession456")
    print(f"Test Case 2 (Not a Moderator): {'Passed' if not test2 else 'Failed'}")

    # Test Case 3: Correct username, wrong password
    test3 = check_mod("admin", "wrongpassword", "adminsession123")
    print(f"Test Case 3 (Wrong Password): {'Passed' if not test3 else 'Failed'}")

    # Test Case 4: Correct credentials, wrong session
    test4 = check_mod("admin", "pass123", "wrongsession")
    print(f"Test Case 4 (Wrong Session): {'Passed' if not test4 else 'Failed'}")

    # Test Case 5: Non-existent user
    test5 = check_mod("unknown", "password", "somesession")
    print(f"Test Case 5 (Non-existent User): {'Passed' if not test5 else 'Failed'}")

if __name__ == "__main__":
    main()