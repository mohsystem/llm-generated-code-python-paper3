import random

# In-memory storage for user credentials (username -> password)
USERS = {
    "user1": "pass123",
    "user2": "secret456",
    "user3": "qwerty"
}

# In-memory storage for generated OTPs (username -> otp)
USER_OTPS = {}

def verify_user(username, password):
    """
    Verifies the user's primary credentials (username and password).
    :param username: The username.
    :param password: The password.
    :return: True if credentials are valid, False otherwise.
    """
    stored_password = USERS.get(username)
    return stored_password is not None and stored_password == password

def generate_and_send_otp(username):
    """
    Generates a random 6-digit OTP, stores it, and returns it.
    In a real application, this would send the OTP via SMS/email.
    :param username: The username for whom to generate the OTP.
    :return: The generated 6-digit OTP as a string, or None if user doesn't exist.
    """
    if username in USERS:
        otp = str(random.randint(100000, 999999))
        USER_OTPS[username] = otp
        # Simulate sending OTP to the user
        print(f"OTP sent for user '{username}'. OTP is: {otp} (for simulation purposes)")
        return otp
    return None

def verify_otp(username, entered_otp):
    """
    Verifies the entered OTP against the stored OTP for a user.
    :param username: The username.
    :param entered_otp: The OTP entered by the user.
    :return: True if the OTP is correct, False otherwise.
    """
    stored_otp = USER_OTPS.get(username)
    if stored_otp and stored_otp == entered_otp:
        # OTP is single-use, remove it after verification
        del USER_OTPS[username]
        return True
    return False

# Main execution block with test cases
if __name__ == "__main__":
    # --- Test Case 1: Successful Login ---
    print("--- Test Case 1: Successful Login ---")
    user1 = "user1"
    pass1 = "pass123"
    if verify_user(user1, pass1):
        print(f"Primary authentication successful for {user1}")
        otp1 = generate_and_send_otp(user1)
        # Simulate user entering the correct OTP
        if verify_otp(user1, otp1):
            print(f"2FA successful. Login complete for {user1}")
        else:
            print("2FA failed. Invalid OTP.")
    else:
        print(f"Primary authentication failed for {user1}")
    print("\n" + "-"*40 + "\n")

    # --- Test Case 2: Incorrect Password ---
    print("--- Test Case 2: Incorrect Password ---")
    user2 = "user2"
    pass2_wrong = "wrongpassword"
    if verify_user(user2, pass2_wrong):
        print(f"Primary authentication successful for {user2}")
        generate_and_send_otp(user2)
    else:
        print(f"Primary authentication failed for {user2}. Incorrect username or password.")
    print("\n" + "-"*40 + "\n")

    # --- Test Case 3: Incorrect Username ---
    print("--- Test Case 3: Incorrect Username ---")
    user3_wrong = "nonexistentuser"
    pass3 = "qwerty"
    if verify_user(user3_wrong, pass3):
        print(f"Primary authentication successful for {user3_wrong}")
        generate_and_send_otp(user3_wrong)
    else:
        print(f"Primary authentication failed for {user3_wrong}. Incorrect username or password.")
    print("\n" + "-"*40 + "\n")

    # --- Test Case 4: Correct Password, Incorrect OTP ---
    print("--- Test Case 4: Correct Password, Incorrect OTP ---")
    user4 = "user3"
    pass4 = "qwerty"
    if verify_user(user4, pass4):
        print(f"Primary authentication successful for {user4}")
        generate_and_send_otp(user4)
        # Simulate user entering a wrong OTP
        wrong_otp = "000000"
        print(f"User '{user4}' enters OTP: {wrong_otp}")
        if verify_otp(user4, wrong_otp):
            print(f"2FA successful. Login complete for {user4}")
        else:
            print(f"2FA failed. Invalid OTP for {user4}")
    else:
        print(f"Primary authentication failed for {user4}")
    print("\n" + "-"*40 + "\n")

    # --- Test Case 5: Another Successful Login ---
    print("--- Test Case 5: Another Successful Login ---")
    user5 = "user2"
    pass5 = "secret456"
    if verify_user(user5, pass5):
        print(f"Primary authentication successful for {user5}")
        otp5 = generate_and_send_otp(user5)
        # Simulate user entering the correct OTP
        if verify_otp(user5, otp5):
            print(f"2FA successful. Login complete for {user5}")
        else:
            print("2FA failed. Invalid OTP.")
    else:
        print(f"Primary authentication failed for {user5}")
    print("\n" + "-"*40 + "\n")