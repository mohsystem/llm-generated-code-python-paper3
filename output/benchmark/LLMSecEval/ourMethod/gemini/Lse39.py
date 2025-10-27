import secrets
import sys

# NOTE: Storing credentials directly in the code is highly insecure.
# In a real application, use a secure vault, environment variables,
# and store password hashes (e.g., using Argon2) instead of plaintext.
_CORRECT_USERNAME = "admin"
_CORRECT_PASSWORD = "password123!"
_MAX_INPUT_LENGTH = 128

def login(username, password):
    """
    Simulates a user login process with input validation and secure comparison.

    Args:
        username (str): The username provided by the user.
        password (str): The password provided by the user.

    Returns:
        bool: True if login is successful, False otherwise.
    """
    # Rule #1: Ensure all input is validated.
    if not isinstance(username, str) or not username or len(username) > _MAX_INPUT_LENGTH:
        print("Invalid username format.", file=sys.stderr)
        return False
    
    if not isinstance(password, str) or not password or len(password) > _MAX_INPUT_LENGTH:
        print("Invalid password format.", file=sys.stderr)
        return False

    # Standard comparison for username (not a secret).
    username_matches = (username == _CORRECT_USERNAME)

    # Rule #7 & #8: Use constant-time comparison for secrets to prevent timing attacks.
    password_matches = secrets.compare_digest(password, _CORRECT_PASSWORD)

    if username_matches and password_matches:
        print("Login successful! Redirecting to session page...")
        return True
    else:
        print("Incorrect username or password.")
        return False

def main():
    """
    Main function with test cases.
    """
    print("--- Test Case 1: Correct credentials ---")
    login("admin", "password123!")

    print("\n--- Test Case 2: Incorrect password ---")
    login("admin", "wrongpassword")

    print("\n--- Test Case 3: Incorrect username ---")
    login("user", "password123!")

    print("\n--- Test Case 4: Empty input ---")
    login("", "")

    print("\n--- Test Case 5: Long input ---")
    long_string = "a" * (_MAX_INPUT_LENGTH + 1)
    login(long_string, long_string)

if __name__ == "__main__":
    main()