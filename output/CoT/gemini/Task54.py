import secrets
import os

# IMPORTANT: In a real-world application, never store passwords in plaintext.
# They should be securely hashed and salted. This is for demonstration purposes only.
_user_database = {
    "alice": "password123",
    "bob": "bob@secret"
}

def verify_credentials(username, password):
    """
    Verifies user credentials against the stored database.
    :param username: The username to check.
    :param password: The password to check.
    :return: True if credentials are valid, False otherwise.
    """
    stored_password = _user_database.get(username)
    return stored_password is not None and stored_password == password

def generate_otp():
    """
    Generates a cryptographically secure 6-digit One-Time Password (OTP).
    :return: A 6-digit OTP as a string.
    """
    # Generate a number between 100000 and 999999
    otp = secrets.randbelow(900000) + 100000
    return str(otp)

def verify_otp(generated_otp, user_input_otp):
    """
    Verifies if the user-provided OTP matches the generated OTP.
    :param generated_otp: The system-generated OTP.
    :param user_input_otp: The OTP entered by the user.
    :return: True if the OTPs match, False otherwise.
    """
    return generated_otp is not None and generated_otp == user_input_otp

def login_process(username, password, otp_input):
    """
    Simulates the full login process for a given user.
    :param username: The user's username.
    :param password: The user's password.
    :param otp_input: The OTP provided by the user for the simulation.
    """
    print(f"--- Attempting login for user: {username} ---")
    if verify_credentials(username, password):
        print("Credentials verified. Generating OTP...")
        otp = generate_otp()
        
        # In a real application, this OTP would be sent to the user via SMS, email, etc.
        # For this simulation, we will print it to the console.
        print(f"Generated OTP (for simulation): {otp}")
        print(f"User provided OTP: {otp_input}")

        if verify_otp(otp, otp_input):
            print("OTP verification successful. Login successful!")
        else:
            print("OTP verification failed. Access denied.")
    else:
        print("Invalid username or password. Access denied.")
    print("-----------------------------------------\n")

def main():
    # Test Case 1: Successful login
    # Simulate correct password and then providing the correct OTP.
    # For the test, we'll "peek" at the OTP to simulate a user receiving and entering it.
    correct_username1 = "alice"
    correct_password1 = "password123"
    if verify_credentials(correct_username1, correct_password1):
        generated_otp1 = generate_otp() # We generate it to pass it to the simulation
        login_process(correct_username1, correct_password1, generated_otp1)

    # Test Case 2: Incorrect password
    login_process("alice", "wrongpassword", "123456")

    # Test Case 3: Correct password, incorrect OTP
    login_process("bob", "bob@secret", "000000")

    # Test Case 4: Non-existent user
    login_process("charlie", "somepassword", "654321")
    
    # Test Case 5: Another successful login
    correct_username2 = "bob"
    correct_password2 = "bob@secret"
    if verify_credentials(correct_username2, correct_password2):
        generated_otp2 = generate_otp()
        login_process(correct_username2, correct_password2, generated_otp2)

if __name__ == "__main__":
    main()