import hmac

# In a real application, these would not be hardcoded.
# The password would be a salted hash, not plaintext.
_CORRECT_USERNAME = "admin"
_CORRECT_PASSWORD = "P@ssw0rd!123"

def check_mod(username, password):
    """
    Securely checks if the provided username and password are correct.
    Uses a constant-time comparison to prevent timing attacks.

    Args:
        username (str): The username provided by the user.
        password (str): The password provided by the user.
    
    Returns:
        bool: True if credentials are correct, False otherwise.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        return False

    # hmac.compare_digest is a constant-time comparison function
    # to help mitigate timing attacks.
    user_match = hmac.compare_digest(_CORRECT_USERNAME, username)
    pass_match = hmac.compare_digest(_CORRECT_PASSWORD, password)

    return user_match and pass_match

# Main block with test cases
if __name__ == "__main__":
    print("Test Case 1: Correct credentials")
    print(f"Input: admin, P@ssw0rd!123")
    print(f"Output: {check_mod('admin', 'P@ssw0rd!123')}")  # Expected: True
    print("--------------------")

    print("Test Case 2: Correct username, incorrect password")
    print(f"Input: admin, wrongpassword")
    print(f"Output: {check_mod('admin', 'wrongpassword')}") # Expected: False
    print("--------------------")

    print("Test Case 3: Incorrect username, correct password")
    print(f"Input: user, P@ssw0rd!123")
    print(f"Output: {check_mod('user', 'P@ssw0rd!123')}")  # Expected: False
    print("--------------------")

    print("Test Case 4: Incorrect credentials")
    print(f"Input: user, password")
    print(f"Output: {check_mod('user', 'password')}")  # Expected: False
    print("--------------------")

    print("Test Case 5: Correct username, password with different length")
    print(f"Input: admin, P@ss")
    print(f"Output: {check_mod('admin', 'P@ss')}")  # Expected: False
    print("--------------------")