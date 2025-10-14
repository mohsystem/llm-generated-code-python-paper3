import secrets

# Note: Storing plaintext passwords is a major security risk.
# In a real-world application, you should store a strong cryptographic hash
# of the password (e.g., using Argon2, scrypt, or bcrypt) and compare the hashes.
# The prompt describes an insecure, sequential comparison which is vulnerable
# to timing attacks. This code implements a secure, constant-time comparison.

def secure_password_compare(user_input_password: str, stored_password: str) -> bool:
    """
    Securely compares two passwords in a way that prevents timing attacks.
    Python's secrets.compare_digest is designed for this purpose.

    :param user_input_password: The password entered by the user.
    :param stored_password: The password that would be read from a file or database.
    :return: True if the passwords match, False otherwise.
    """
    # secrets.compare_digest mitigates timing attacks by taking an amount of
    # time that is dependent on the length of the strings, but not their contents.
    return secrets.compare_digest(user_input_password, stored_password)

def main():
    """Main function with test cases."""
    # This would be the password stored securely (as a hash in a real app).
    stored_password = "S3cureP@ssw0rd!23"

    print("--- Python: Test Cases for Secure Password Comparison ---")

    # Test Case 1: Correct password
    input1 = "S3cureP@ssw0rd!23"
    result1 = secure_password_compare(input1, stored_password)
    print(f"Test 1 (Correct Match): {'PASS' if result1 else 'FAIL'}")

    # Test Case 2: Incorrect password (different case)
    input2 = "s3curep@ssw0rd!23"
    result2 = secure_password_compare(input2, stored_password)
    print(f"Test 2 (Case Mismatch): {'PASS' if not result2 else 'FAIL'}")

    # Test Case 3: Incorrect password (different length)
    input3 = "S3cureP@ssw0rd!"
    result3 = secure_password_compare(input3, stored_password)
    print(f"Test 3 (Length Mismatch): {'PASS' if not result3 else 'FAIL'}")

    # Test Case 4: Incorrect password (same length, different char)
    input4 = "S3cureP@ssw0rd!24"
    result4 = secure_password_compare(input4, stored_password)
    print(f"Test 4 (Character Mismatch): {'PASS' if not result4 else 'FAIL'}")

    # Test Case 5: Empty string vs stored password
    input5 = ""
    result5 = secure_password_compare(input5, stored_password)
    print(f"Test 5 (Empty Input): {'PASS' if not result5 else 'FAIL'}")

if __name__ == "__main__":
    main()