import hmac

# In a real application, this would be a secure database connection.
# Passwords must be stored as salted hashes using a strong algorithm like Argon2, scrypt, or bcrypt.
# This dictionary is a simplified simulation for demonstration purposes.
USER_DATABASE = {
    # Storing "hashed" passwords. Real hashes are much longer.
    # Example: "password123" -> some_hash_value
    "admin": "hashed_password_for_admin",
    # Example: "testuser" -> another_password
    "testuser": "hashed_password_for_user"
}

def login(username, password):
    """
    Simulates a user login process.

    :param username: The username provided by the user.
    :param password: The password provided by the user.
    :return: A string indicating the result: "success", "cant_login", or "internal_server_error".
    """
    try:
        # 1. Input Validation: Ensure username and password are not None or empty.
        if not username or not password:
            return "cant_login"

        # 2. Database Lookup: Retrieve the stored "hash" for the user.
        stored_hashed_password = USER_DATABASE.get(username)

        # 3. User Existence and Password Verification
        # Using hmac.compare_digest for constant-time string comparison to prevent timing attacks.
        # It's crucial to compare against a value even if the user doesn't exist to keep timing consistent.
        
        # In a real app, you would hash the input password with the user's salt
        # and then compare the result with the stored hash.
        # Here, we simulate this by comparing the plaintext password with the stored "hash".
        
        is_match = False
        if stored_hashed_password:
             is_match = hmac.compare_digest(stored_hashed_password, password)
        else:
             # If user does not exist, perform a dummy comparison to prevent timing leaks.
             hmac.compare_digest("dummy_hash_to_prevent_timing_attack", password)


        if is_match:
            return "success"
        else:
            # Generic error for both non-existent user and wrong password to prevent user enumeration.
            return "cant_login"

    except Exception as e:
        # 4. Error Handling: Catch any unexpected exceptions.
        print(f"An unexpected error occurred: {e}")
        return "internal_server_error"

def main():
    """Main function to run test cases."""
    print("--- Running Test Cases ---")
    
    # Test Case 1: Successful login
    result1 = login("admin", "hashed_password_for_admin")
    print(f"Test Case 1 (Correct Credentials): {result1}")

    # Test Case 2: Incorrect password
    result2 = login("admin", "wrong_password")
    print(f"Test Case 2 (Incorrect Password): {result2}")

    # Test Case 3: Non-existent user
    result3 = login("unknown_user", "some_password")
    print(f"Test Case 3 (Non-existent User): {result3}")

    # Test Case 4: None input
    result4 = login(None, "some_password")
    print(f"Test Case 4 (None Username): {result4}")

    # Test Case 5: Empty input
    result5 = login("testuser", "")
    print(f"Test Case 5 (Empty Password): {result5}")

    print("--- Test Cases Finished ---")

if __name__ == "__main__":
    main()