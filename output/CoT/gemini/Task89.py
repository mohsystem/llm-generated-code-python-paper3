import os
import secrets

def compare_password(filename, user_input):
    """
    WARNING: Storing passwords in plaintext is extremely insecure.
    In a real-world application, you should always use a strong, salted,
    one-way hashing algorithm like Argon2, scrypt, or bcrypt to store password hashes,
    not the passwords themselves. This implementation is for demonstration purposes only.

    Compares a user-provided password with one stored in a file.
    This function uses a constant-time comparison to mitigate timing attacks.
    For production code, it is highly recommended to use Python's `secrets.compare_digest`.

    Args:
        filename (str): The path to the file containing the stored password.
        user_input (str): The password entered by the user.

    Returns:
        bool: True if the passwords match, False otherwise.
    """
    try:
        with open(filename, 'r') as f:
            # Read the password and remove leading/trailing whitespace, including newline
            stored_password = f.readline().strip()
    except IOError:
        print(f"Error: Could not read file at {filename}")
        return False

    # Note: A more robust and recommended way in Python is to use the secrets module:
    # return secrets.compare_digest(stored_password, user_input)
    # The manual implementation below is for demonstration of the concept.

    stored_bytes = stored_password.encode('utf-8')
    user_bytes = user_input.encode('utf-8')

    # Length check is performed first. This can leak password length information.
    if len(stored_bytes) != len(user_bytes):
        return False

    # Constant-time comparison
    diff = 0
    for b1, b2 in zip(stored_bytes, user_bytes):
        diff |= b1 ^ b2
    
    return diff == 0

def main():
    test_filename = "password.txt"
    correct_password = "S3cur3P@ssw0rd!"

    # Setup: Create a dummy password file for testing
    try:
        with open(test_filename, 'w') as f:
            f.write(correct_password)
    except IOError:
        print("Failed to create test password file.")
        return

    print("--- Python Test Cases ---")
    # Test Case 1: Correct password
    result1 = compare_password(test_filename, "S3cur3P@ssw0rd!")
    print(f"Test 1 (Correct): {'PASS' if result1 else 'FAIL'}")

    # Test Case 2: Incorrect password (different first character)
    result2 = compare_password(test_filename, "X3cur3P@ssw0rd!")
    print(f"Test 2 (Incorrect, first char): {'PASS' if not result2 else 'FAIL'}")

    # Test Case 3: Incorrect password (different last character)
    result3 = compare_password(test_filename, "S3cur3P@ssw0rd?")
    print(f"Test 3 (Incorrect, last char): {'PASS' if not result3 else 'FAIL'}")

    # Test Case 4: Incorrect password (shorter)
    result4 = compare_password(test_filename, "S3cur3")
    print(f"Test 4 (Incorrect, shorter): {'PASS' if not result4 else 'FAIL'}")

    # Test Case 5: Incorrect password (longer)
    result5 = compare_password(test_filename, "S3cur3P@ssw0rd!Extra")
    print(f"Test 5 (Incorrect, longer): {'PASS' if not result5 else 'FAIL'}")

    # Cleanup: Delete the test file
    if os.path.exists(test_filename):
        os.remove(test_filename)

if __name__ == "__main__":
    main()