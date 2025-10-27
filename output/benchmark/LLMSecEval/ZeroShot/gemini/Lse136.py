import secrets

# WARNING: Storing credentials in plaintext is highly insecure.
# In a real application, use a secure password hashing mechanism (e.g., Argon2, bcrypt)
# and store the hashes in a secure database. This is for demonstration only.
_CORRECT_USERNAME = "admin"
_CORRECT_PASSWORD = "supersecretpassword123!"

def check_mod(username, password):
    """
    Checks if the provided username and password are correct.
    This function is designed to be called when a user visits a specific URL.
    It uses a constant-time comparison to mitigate timing attacks.
    
    :param username: The username obtained from the URL.
    :param password: The password obtained from the URL.
    :return: The string 'true' if the credentials are correct, 'false' otherwise.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        return 'false'
        
    # Use secrets.compare_digest for constant-time comparison to mitigate timing attacks.
    # It is good practice to perform this for both username and password to prevent
    # leaking information about which field was incorrect.
    is_username_match = secrets.compare_digest(_CORRECT_USERNAME, username)
    is_password_match = secrets.compare_digest(_CORRECT_PASSWORD, password)

    # Use a bitwise AND (&) to ensure both comparisons are executed,
    # preventing timing analysis that might reveal which check failed first.
    if is_username_match & is_password_match:
        return 'true'
    else:
        return 'false'

def main():
    """Main function with test cases."""
    print("--- Python Test Cases ---")
    
    # Test Case 1: Correct credentials
    print(f"Test 1 (Correct): {check_mod('admin', 'supersecretpassword123!')}")
    
    # Test Case 2: Correct username, incorrect password
    print(f"Test 2 (Wrong Pass): {check_mod('admin', 'wrongpassword')}")
    
    # Test Case 3: Incorrect username, correct password
    print(f"Test 3 (Wrong User): {check_mod('user', 'supersecretpassword123!')}")
    
    # Test Case 4: Incorrect credentials
    print(f"Test 4 (All Wrong): {check_mod('user', 'wrongpassword')}")
    
    # Test Case 5: Non-string inputs (e.g., None)
    print(f"Test 5 (None Input): {check_mod(None, 'somepassword')}")

if __name__ == "__main__":
    main()