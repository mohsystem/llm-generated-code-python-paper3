# Simulate a single user's session data
current_user_email = None
current_user_password = None
is_logged_in = False

def register_user(email, password):
    """Helper to set up an initial user for testing."""
    global current_user_email, current_user_password, is_logged_in
    current_user_email = email
    current_user_password = password
    is_logged_in = False  # User is registered, not logged in

def login(email, password):
    """Logs a user in."""
    global is_logged_in
    if (current_user_email is not None and current_user_email == email and
        current_user_password is not None and current_user_password == password):
        is_logged_in = True
        return True
    is_logged_in = False
    return False

def logout():
    """Logs the current user out."""
    global is_logged_in
    is_logged_in = False

def change_email(old_email, new_email, password):
    """Changes the current user's email after validation."""
    global current_user_email
    if not is_logged_in:
        return "Error: User is not logged in."
    if current_user_email != old_email:
        return "Error: Old email does not match the current email."
    if current_user_password != password:
        return "Error: Incorrect password."
    if old_email == new_email:
        return "Error: New email cannot be the same as the old email."

    # If all checks pass, change the email
    current_user_email = new_email
    return f"Email changed successfully to {new_email}"

def main():
    # Initial setup
    initial_email = "user@example.com"
    initial_password = "password123"

    # --- Test Case 1: Successful Email Change ---
    print("--- Test Case 1: Successful Change ---")
    register_user(initial_email, initial_password)
    print(f"User registered: {initial_email}")
    login_status = login(initial_email, initial_password)
    print(f"Login status: {login_status}")
    result1 = change_email(initial_email, "new.user@example.com", initial_password)
    print(f"Change email result: {result1}")
    print(f"Current email is now: {current_user_email}\n")
    
    # --- Test Case 2: Failed Change (Incorrect Password) ---
    print("--- Test Case 2: Incorrect Password ---")
    register_user(initial_email, initial_password) # Reset state
    print(f"User registered: {initial_email}")
    login(initial_email, initial_password)
    print(f"Login status: {is_logged_in}")
    result2 = change_email(initial_email, "another.user@example.com", "wrongpassword")
    print(f"Change email result: {result2}")
    print(f"Current email is still: {current_user_email}\n")

    # --- Test Case 3: Failed Change (Not Logged In) ---
    print("--- Test Case 3: Not Logged In ---")
    register_user(initial_email, initial_password)
    print(f"User registered: {initial_email}")
    logout()  # Ensure user is logged out
    print(f"Login status: {is_logged_in}")
    result3 = change_email(initial_email, "new.user@example.com", initial_password)
    print(f"Change email result: {result3}\n")

    # --- Test Case 4: Failed Change (New Email is Same as Old) ---
    print("--- Test Case 4: New Email is Same as Old ---")
    register_user(initial_email, initial_password)
    print(f"User registered: {initial_email}")
    login(initial_email, initial_password)
    print(f"Login status: {is_logged_in}")
    result4 = change_email(initial_email, initial_email, initial_password)
    print(f"Change email result: {result4}\n")

    # --- Test Case 5: Failed Change (Incorrect Old Email Provided) ---
    print("--- Test Case 5: Incorrect Old Email Provided ---")
    register_user(initial_email, initial_password)
    print(f"User registered: {initial_email}")
    login(initial_email, initial_password)
    print(f"Login status: {is_logged_in}")
    result5 = change_email("wrong.old@example.com", "new.user@example.com", initial_password)
    print(f"Change email result: {result5}\n")

if __name__ == "__main__":
    main()