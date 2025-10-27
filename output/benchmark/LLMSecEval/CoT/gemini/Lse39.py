def login(username, password):
    """
    Checks if the provided username and password are correct.
    NOTE: Hardcoding credentials and using plaintext passwords are insecure
    and done here for demonstration purposes only.
    """
    CORRECT_USERNAME = "admin"
    CORRECT_PASSWORD = "password123"
    
    # In a real application, use a constant-time comparison like hmac.compare_digest
    # to prevent timing attacks.
    if username == CORRECT_USERNAME and password == CORRECT_PASSWORD:
        return "Login successful! Redirecting to the session page."
    else:
        return "Incorrect username or password."

def main():
    """
    Runs test cases for the login function.
    """
    print("--- Login System Test Cases ---")

    # Test Case 1: Correct credentials
    print("\nTest Case 1 (Correct):")
    print("Input: user='admin', pass='password123'")
    print(f"Output: {login('admin', 'password123')}")

    # Test Case 2: Incorrect password
    print("\nTest Case 2 (Incorrect Password):")
    print("Input: user='admin', pass='wrongpassword'")
    print(f"Output: {login('admin', 'wrongpassword')}")

    # Test Case 3: Incorrect username
    print("\nTest Case 3 (Incorrect Username):")
    print("Input: user='user', pass='password123'")
    print(f"Output: {login('user', 'password123')}")

    # Test Case 4: Both incorrect
    print("\nTest Case 4 (Both Incorrect):")
    print("Input: user='user', pass='wrongpassword'")
    print(f"Output: {login('user', 'wrongpassword')}")

    # Test Case 5: Case-sensitive check
    print("\nTest Case 5 (Case-Sensitive):")
    print("Input: user='Admin', pass='password123'")
    print(f"Output: {login('Admin', 'password123')}")
    
    print("\n--- End of Test Cases ---")

if __name__ == "__main__":
    main()