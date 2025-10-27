import base64

# --- Mock User Database and Session ---
# In a real application, this would be a database.
USER_DATABASE = {}
# In a real application, session management would be more robust.
CURRENT_USER = None

# --- Security Utilities (Mocks) ---
def hash_password(password):
    """
    MOCK HASHING: NOT FOR PRODUCTION USE.
    Use libraries like bcrypt or passlib in a real application.
    """
    salted_password = "salted_" + password
    return base64.b64encode(salted_password.encode()).decode()

def verify_password(plain_password, stored_hash):
    """
    MOCK VERIFICATION: NOT FOR PRODUCTION USE.
    This comparison should be done in a constant-time manner to prevent timing attacks.
    """
    if not stored_hash or not plain_password:
        return False
    return hash_password(plain_password) == stored_hash
    
def is_valid_email_format(email):
    """Basic email format validation."""
    if not email:
        return False
    # A simple check, a more robust regex would be used in production.
    return "@" in email and "." in email

# --- Core Functionality ---
def login(username, password):
    """Logs a user in by setting the global CURRENT_USER."""
    global CURRENT_USER
    user = USER_DATABASE.get(username)
    if user and verify_password(password, user['password_hash']):
        CURRENT_USER = user
        return True
    CURRENT_USER = None
    return False

def logout():
    """Logs the current user out."""
    global CURRENT_USER
    CURRENT_USER = None

def change_email(old_email, new_email, password):
    """
    Changes the user's email address after performing security checks.
    
    Args:
        old_email (str): The user's current email address for verification.
        new_email (str): The desired new email address.
        password (str): The user's current password for authorization.
        
    Returns:
        str: A string indicating the result of the operation.
    """
    # 1. Check if a user is logged in
    if not CURRENT_USER:
        return "Error: You must be logged in to change your email."

    # 2. Verify the provided password is correct for the logged-in user
    if not verify_password(password, CURRENT_USER['password_hash']):
        return "Error: Incorrect password."
        
    # 3. Verify the provided old email matches the one on record
    if CURRENT_USER['email'] != old_email:
        return "Error: The old email address does not match our records."

    # 4. Check if the new email is the same as the old email
    if old_email == new_email:
        return "Error: New email cannot be the same as the old email."
        
    # 5. Validate the new email format
    if not is_valid_email_format(new_email):
        return "Error: Invalid new email format."
        
    # All checks passed, update the email
    CURRENT_USER['email'] = new_email
    return f"Success: Email has been updated to {new_email}"


# --- Main block with test cases ---
if __name__ == "__main__":
    # Setup: Create a user and add to the mock database
    username = "testuser"
    initial_email = "user@example.com"
    initial_password = "Password123!"
    
    USER_DATABASE[username] = {
        'username': username,
        'email': initial_email,
        'password_hash': hash_password(initial_password)
    }

    print("--- Test Case 1: Successful Email Change ---")
    login(username, initial_password)
    print(f"Login successful for: {CURRENT_USER['username'] if CURRENT_USER else 'none'}")
    result1 = change_email(initial_email, "new.user@example.com", initial_password)
    print(f"Result: {result1}")
    print(f"Current email: {CURRENT_USER['email'] if CURRENT_USER else 'N/A'}")
    logout()
    print("\n-------------------------------------------------\n")

    # Reset user email for next tests
    USER_DATABASE[username]['email'] = initial_email

    print("--- Test Case 2: Failure - Not Logged In ---")
    print("Current user is logged out.")
    result2 = change_email(initial_email, "another.email@example.com", initial_password)
    print(f"Result: {result2}")
    print("\n-------------------------------------------------\n")

    print("--- Test Case 3: Failure - Incorrect Password ---")
    login(username, initial_password)
    print(f"Login successful for: {CURRENT_USER['username'] if CURRENT_USER else 'none'}")
    result3 = change_email(initial_email, "another.email@example.com", "WrongPassword!")
    print(f"Result: {result3}")
    print(f"Email was not changed: {CURRENT_USER['email']}")
    logout()
    print("\n-------------------------------------------------\n")

    print("--- Test Case 4: Failure - Incorrect Old Email ---")
    login(username, initial_password)
    print(f"Login successful for: {CURRENT_USER['username'] if CURRENT_USER else 'none'}")
    result4 = change_email("wrong.old@example.com", "another.email@example.com", initial_password)
    print(f"Result: {result4}")
    print(f"Email was not changed: {CURRENT_USER['email']}")
    logout()
    print("\n-------------------------------------------------\n")

    print("--- Test Case 5: Failure - New Email is Same as Old ---")
    login(username, initial_password)
    print(f"Login successful for: {CURRENT_USER['username'] if CURRENT_USER else 'none'}")
    result5 = change_email(initial_email, initial_email, initial_password)
    print(f"Result: {result5}")
    print(f"Email was not changed: {CURRENT_USER['email']}")
    logout()
    print("\n-------------------------------------------------\n")