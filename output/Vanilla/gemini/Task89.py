import os

def create_password_file(filename, password):
    """Creates a dummy file with the given password."""
    try:
        with open(filename, 'w') as f:
            f.write(password)
    except IOError as e:
        print(f"Error creating password file: {e}")

def compare_password(filename, user_input):
    """
    Compares the password in a file with the user-provided password
    by checking each character sequentially.
    """
    try:
        with open(filename, 'r') as f:
            stored_password = f.read()

        # First, check if the lengths are the same.
        if len(stored_password) != len(user_input):
            return False

        # Compare each character sequentially
        for i in range(len(stored_password)):
            if stored_password[i] != user_input[i]:
                return False  # Mismatch found

        # If the loop completes, all characters matched
        return True

    except IOError as e:
        print(f"Error reading password file: {e}")
        return False

if __name__ == "__main__":
    filename = "password.txt"
    correct_password = "P@ssw0rd123"

    # Create the password file for testing
    create_password_file(filename, correct_password)

    # --- Test Cases ---
    test_passwords = [
        "P@ssw0rd123",    # 1. Correct password
        "p@ssw0rd123",    # 2. Incorrect case
        "P@ssw0rd",       # 3. Incorrect length (shorter)
        "P@ssw0rd124",    # 4. Same length, different character
        ""                # 5. Empty password
    ]
    
    print("--- Python Test Cases ---")
    for test in test_passwords:
        is_match = compare_password(filename, test)
        result_str = "Match" if is_match else "No Match"
        print(f'Testing with "{test}": {result_str}')

    # Clean up the created file
    if os.path.exists(filename):
        os.remove(filename)