# In-memory database to store user information.
# In a real application, this would be a persistent database.
user_database = {}

# Represents the currently logged-in user. None if no one is logged in.
logged_in_user = None

def setup_database():
    """Initializes the database with sample users."""
    global user_database
    # In a real app, passwords should be salted and hashed.
    user_database = {
        "john.doe": {"email": "john.d@example.com", "password": "password123"},
        "jane.doe": {"email": "jane.d@example.com", "password": "password456"}
    }

def login(username, password):
    """
    Simulates a user logging in.
    :param username: The username of the user.
    :param password: The password of the user.
    :return: True if login is successful, False otherwise.
    """
    global logged_in_user
    user = user_database.get(username)
    if user and user["password"] == password:
        logged_in_user = username
        print(f"Login successful for: {username}")
        return True
    print(f"Login failed for: {username}")
    return False

def logout():
    """Simulates a user logging out."""
    global logged_in_user
    if logged_in_user:
        print(f"User {logged_in_user} logged out.")
        logged_in_user = None

def change_email(old_email, new_email, confirm_password):
    """
    Changes the email for the currently logged-in user.
    :param old_email: The user's current email address.
    :param new_email: The desired new email address.
    :param confirm_password: The user's password for verification.
    :return: A status message indicating success or failure.
    """
    # 1. Authorization: Check if a user is logged in.
    if not logged_in_user:
        return "Error: You must be logged in to change your email."

    current_user_data = user_database.get(logged_in_user)

    # 2. Validation: Check if the provided old email matches the logged-in user's record.
    if not current_user_data or current_user_data["email"] != old_email:
        return "Error: The old email address provided is incorrect."
        
    # 3. Authentication: Verify the user's password.
    # NOTE: In a real system, use a constant-time comparison for security.
    if current_user_data["password"] != confirm_password:
        return "Error: Incorrect password."

    # 4. Input Validation: Check if the new email is not null or empty
    if not new_email or "@" not in new_email:
        return "Error: New email is not valid."
        
    # 5. Uniqueness Check: Ensure the new email is not already in use by another user.
    for username, data in user_database.items():
        if data["email"].lower() == new_email.lower() and username != logged_in_user:
            return "Error: The new email address is already in use by another account."

    # 6. Update the email
    user_database[logged_in_user]["email"] = new_email
    return f"Success: Email has been changed to {new_email}"

def main():
    """Main function to run test cases."""
    setup_database()

    print("--- Test Case 1: Successful Email Change ---")
    login("john.doe", "password123")
    result1 = change_email("john.d@example.com", "john.new@example.com", "password123")
    print(f"Result: {result1}")
    print(f"Current user info: {user_database['john.doe']}")
    logout()
    print("\n" + "-"*44 + "\n")

    print("--- Test Case 2: Attempt to Change Email While Logged Out ---")
    result2 = change_email("jane.d@example.com", "jane.new@example.com", "password456")
    print(f"Result: {result2}")
    print("\n" + "-"*44 + "\n")
    
    print("--- Test Case 3: Incorrect Password ---")
    login("jane.doe", "password456")
    result3 = change_email("jane.d@example.com", "jane.new@example.com", "wrongpassword")
    print(f"Result: {result3}")
    logout()
    print("\n" + "-"*44 + "\n")

    print("--- Test Case 4: Incorrect Old Email ---")
    login("john.doe", "password123")
    result4 = change_email("wrong.email@example.com", "john.another@example.com", "password123")
    print(f"Result: {result4}")
    logout()
    print("\n" + "-"*44 + "\n")

    print("--- Test Case 5: New Email Already in Use ---")
    login("john.doe", "password123")
    # john tries to take jane's email
    result5 = change_email("john.new@example.com", "jane.d@example.com", "password123")
    print(f"Result: {result5}")
    logout()
    print("\n" + "-"*44 + "\n")

if __name__ == "__main__":
    main()