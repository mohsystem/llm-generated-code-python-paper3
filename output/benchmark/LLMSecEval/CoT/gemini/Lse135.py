import hmac

# NOTE: Storing credentials in plaintext is a major security risk.
# In a real application, use a secure method like hashed and salted passwords.
_CORRECT_USERNAME = "admin"
_CORRECT_PASSWORD = "password123"

def check_mod(username, password):
    """
    Checks if the provided username and password are correct.

    :param username: The username to check.
    :param password: The password to check.
    :return: True if credentials are correct, False otherwise.
    """
    if not username or not password:
        return False

    is_username_correct = hmac.compare_digest(username, _CORRECT_USERNAME)
    
    # Use hmac.compare_digest for constant-time comparison to prevent timing attacks.
    is_password_correct = hmac.compare_digest(password, _CORRECT_PASSWORD)

    return is_username_correct and is_password_correct

# Main execution block with test cases
if __name__ == "__main__":
    # Test Case 1: Correct username and password
    print(f"Test Case 1 (Correct credentials): {check_mod('admin', 'password123')}")

    # Test Case 2: Correct username, incorrect password
    print(f"Test Case 2 (Incorrect password): {check_mod('admin', 'wrongpassword')}")

    # Test Case 3: Incorrect username, correct password
    print(f"Test Case 3 (Incorrect username): {check_mod('user', 'password123')}")

    # Test Case 4: Incorrect username and password
    print(f"Test Case 4 (Incorrect credentials): {check_mod('user', 'wrongpassword')}")

    # Test Case 5: Empty inputs
    print(f"Test Case 5 (Empty input): {check_mod('admin', '')}")