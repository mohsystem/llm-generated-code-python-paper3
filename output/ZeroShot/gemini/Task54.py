import secrets
import string

# In-memory storage for user credentials.
# WARNING: Storing plain-text passwords is insecure. Use hashed passwords in production.
USER_DATABASE = {
    "alice": "password123",
    "bob": "bob@1234"
}

# In-memory storage for one-time passwords.
OTP_STORAGE = {}

def login(username, password):
    """
    Factor 1: Validates username and password.
    
    Args:
        username (str): The user's username.
        password (str): The user's password.
        
    Returns:
        bool: True if credentials are valid, False otherwise.
    """
    stored_password = USER_DATABASE.get(username)
    return stored_password is not None and stored_password == password

def generate_and_send_otp(username):
    """
    Generates and "sends" a 6-digit OTP for the user.
    In a real application, this would be sent via SMS or email.
    
    Args:
        username (str): The user to generate an OTP for.
        
    Returns:
        str: The generated OTP, or None if the user does not exist.
    """
    if username not in USER_DATABASE:
        return None
    
    # Generate a cryptographically secure 6-digit OTP
    otp = "".join(secrets.choice(string.digits) for _ in range(6))
    
    # Store the OTP for validation
    OTP_STORAGE[username] = otp
    
    # Simulate sending the OTP to the user
    print(f"OTP sent to {username}. Your OTP is: {otp}")
    return otp

def validate_otp(username, otp):
    """
    Factor 2: Validates the provided OTP for the user.
    
    Args:
        username (str): The user's username.
        otp (str): The one-time password provided by the user.
        
    Returns:
        bool: True if the OTP is valid, False otherwise.
    """
    stored_otp = OTP_STORAGE.get(username)
    if stored_otp and secrets.compare_digest(stored_otp, otp):
        # Invalidate the OTP after use
        del OTP_STORAGE[username]
        return True
    return False

def main():
    """Main function to run test cases."""
    print("--- Running 2FA Login Test Cases ---")

    # Test Case 1: Successful Login
    print("\n--- Test Case 1: Successful Login ---")
    user1, pass1 = "alice", "password123"
    print(f"Attempting to log in user: {user1}")
    if login(user1, pass1):
        print("Step 1 (Password) successful.")
        generated_otp1 = generate_and_send_otp(user1)
        # Simulate user inputting the correct OTP
        if validate_otp(user1, generated_otp1):
            print(f"Step 2 (OTP) successful. Login successful for {user1}!")
        else:
            print("Step 2 (OTP) failed. Login failed.")
    else:
        print("Step 1 (Password) failed. Invalid username or password.")

    # Test Case 2: Invalid Password
    print("\n--- Test Case 2: Invalid Password ---")
    user2, pass2 = "bob", "wrongpassword"
    print(f"Attempting to log in user: {user2}")
    if login(user2, pass2):
        print("Step 1 (Password) successful.")
        generate_and_send_otp(user2)
    else:
        print("Step 1 (Password) failed. Invalid username or password.")

    # Test Case 3: Invalid Username
    print("\n--- Test Case 3: Invalid Username ---")
    user3, pass3 = "charlie", "password123"
    print(f"Attempting to log in user: {user3}")
    if login(user3, pass3):
        print("Step 1 (Password) successful.")
    else:
        print("Step 1 (Password) failed. Invalid username or password.")

    # Test Case 4: Incorrect OTP
    print("\n--- Test Case 4: Incorrect OTP ---")
    user4, pass4 = "bob", "bob@1234"
    print(f"Attempting to log in user: {user4}")
    if login(user4, pass4):
        print("Step 1 (Password) successful.")
        generate_and_send_otp(user4)
        # Simulate user inputting an incorrect OTP
        incorrect_otp = "111111"
        print(f"User provides OTP: {incorrect_otp}")
        if validate_otp(user4, incorrect_otp):
            print(f"Step 2 (OTP) successful. Login successful for {user4}!")
        else:
            print("Step 2 (OTP) failed. Login failed.")
    else:
        print("Step 1 (Password) failed. Invalid username or password.")

    # Test Case 5: Full successful flow for the second user
    print("\n--- Test Case 5: Another Successful Login ---")
    user5, pass5 = "bob", "bob@1234"
    print(f"Attempting to log in user: {user5}")
    if login(user5, pass5):
        print("Step 1 (Password) successful.")
        generated_otp5 = generate_and_send_otp(user5)
        if validate_otp(user5, generated_otp5):
            print(f"Step 2 (OTP) successful. Login successful for {user5}!")
        else:
            print("Step 2 (OTP) failed. Login failed.")
    else:
        print("Step 1 (Password) failed. Invalid username or password.")

if __name__ == "__main__":
    main()