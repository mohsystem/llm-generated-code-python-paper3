import secrets

# WARNING: This is a simplified example for demonstration purposes only.
# DO NOT use hardcoded credentials or plaintext password comparison in production applications.
# In a real-world scenario, passwords should be securely stored as salted hashes
# using a strong algorithm like Argon2, scrypt, or PBKDF2, and credentials should
# be managed through a secure configuration or secrets management system.
CORRECT_USERNAME = "admin"
CORRECT_PASSWORD = "Pa$$w0rd123!"

def check_mod(username, password):
    """
    Checks if the provided username and password are correct.
    This function simulates checking credentials from a form.

    Args:
        username (str): The username to check.
        password (str): The password to check.

    Returns:
        bool: True if the credentials are correct, False otherwise.
    """
    # Rule#1: Ensure all input is validated.
    if not isinstance(username, str) or not isinstance(password, str):
        return False

    # Username can be compared directly.
    username_match = (username == CORRECT_USERNAME)

    # Use a constant-time comparison for the password to mitigate timing attacks.
    # secrets.compare_digest is the recommended way to do this for secrets.
    password_match = secrets.compare_digest(password, CORRECT_PASSWORD)

    return username_match and password_match

def main():
    """ Main function with 5 test cases """
    print("Test Case 1: Correct credentials")
    print(f"Input: user='admin', pass='Pa$$w0rd123!'")
    print(f"Result: {check_mod('admin', 'Pa$$w0rd123!')}")  # Expected: True

    print("\nTest Case 2: Incorrect username")
    print(f"Input: user='user', pass='Pa$$w0rd123!'")
    print(f"Result: {check_mod('user', 'Pa$$w0rd123!')}")  # Expected: False

    print("\nTest Case 3: Incorrect password")
    print(f"Input: user='admin', pass='wrongpassword'")
    print(f"Result: {check_mod('admin', 'wrongpassword')}") # Expected: False

    print("\nTest Case 4: Non-string input (e.g., None)")
    print(f"Input: user=None, pass='Pa$$w0rd123!'")
    print(f"Result: {check_mod(None, 'Pa$$w0rd123!')}")    # Expected: False
    
    print("\nTest Case 5: Empty inputs")
    print(f"Input: user='', pass=''")
    print(f"Result: {check_mod('', '')}")                 # Expected: False

if __name__ == "__main__":
    main()