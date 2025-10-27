import hmac

# NOTE: Storing credentials in plaintext is a major security risk.
# In a real application, use a strong, salted hashing algorithm (e.g., Argon2, bcrypt)
# to store password hashes and compare against the hash of the user-provided password.
# These are hardcoded for demonstration purposes only.
CORRECT_USERNAME = "admin"
CORRECT_PASSWORD = "password123"

def check_mod(username, password):
    """
    Simulates checking a username and password from a URL.
    Returns "true" if credentials are correct, "false" otherwise.

    Args:
        username (str): The username to check.
        password (str): The password to check.

    Returns:
        str: "true" on success, "false" on failure.
    """
    if not isinstance(username, str) or not isinstance(password, str):
        return "false"
        
    # Use hmac.compare_digest for constant-time comparison to prevent timing attacks.
    # It is good practice to use it for both username and password.
    is_username_correct = hmac.compare_digest(CORRECT_USERNAME, username)
    is_password_correct = hmac.compare_digest(CORRECT_PASSWORD, password)

    if is_username_correct and is_password_correct:
        return "true"
    else:
        return "false"

def main():
    """ Main function with test cases """
    test_cases = [
        ("admin", "password123"),      # 1. Correct credentials
        ("admin", "wrongpassword"),     # 2. Correct user, wrong password
        ("user", "password123"),      # 3. Wrong user, correct password
        ("user", "wrongpassword"),      # 4. Wrong credentials
        ("", "")                       # 5. Empty credentials
    ]

    print("Running test cases...")
    for i, (username, password) in enumerate(test_cases):
        result = check_mod(username, password)
        print(f"Test Case {i + 1}:")
        print(f"  Username: \"{username}\"")
        print(f"  Password: \"{password}\"")
        print(f"  Result: {result}\n")

if __name__ == "__main__":
    main()