user_database = {}

def add_user(email, password):
    """Adds a new user to the database."""
    if email not in user_database:
        user_database[email] = {"password": password, "is_logged_in": False}

def login(email, password):
    """Logs a user in."""
    if email in user_database and user_database[email]["password"] == password:
        user_database[email]["is_logged_in"] = True
        return True
    return False

def logout(email):
    """Logs a user out."""
    if email in user_database:
        user_database[email]["is_logged_in"] = False

def change_email(old_email, new_email, confirm_password):
    """Changes a user's email after verifying credentials."""
    if old_email not in user_database:
        return "Error: Old email does not exist."

    user = user_database[old_email]

    if not user["is_logged_in"]:
        return "Error: User must be logged in to change email."

    if user["password"] != confirm_password:
        return "Error: Incorrect password."
        
    if new_email in user_database:
        return "Error: New email is already taken."

    # In Python, we can pop the old entry and add a new one
    user_data = user_database.pop(old_email)
    user_database[new_email] = user_data
    return f"Success: Email changed from {old_email} to {new_email}."

def main():
    # Setup: Add some users to our database
    add_user("user1@example.com", "password123")
    add_user("user2@example.com", "securepass456")

    print("--- Test Case 1: Successful Email Change ---")
    login("user1@example.com", "password123")
    print(f"Login status for user1: {user_database.get('user1@example.com', {}).get('is_logged_in', 'Not Found')}")
    result1 = change_email("user1@example.com", "new.user1@example.com", "password123")
    print(result1)
    print(f"Database contains new.user1@example.com: {'new.user1@example.com' in user_database}")
    print(f"Database contains user1@example.com: {'user1@example.com' in user_database}")
    print()

    print("--- Test Case 2: Failed Change (Incorrect Password) ---")
    login("user2@example.com", "securepass456")
    result2 = change_email("user2@example.com", "another.user@example.com", "wrongpassword")
    print(result2)
    print()

    print("--- Test Case 3: Failed Change (User Not Logged In) ---")
    logout("user2@example.com")  # Make sure user is logged out
    result3 = change_email("user2@example.com", "new.user2@example.com", "securepass456")
    print(result3)
    print()

    print("--- Test Case 4: Failed Change (Old Email Not Found) ---")
    result4 = change_email("nonexistent@example.com", "anything@example.com", "anypassword")
    print(result4)
    print()

    print("--- Test Case 5: Logout and then Fail Change ---")
    print("User 'user2@example.com' attempts another change after logging out.")
    logout("user2@example.com")
    print(f"Login status for user2: {user_database.get('user2@example.com', {}).get('is_logged_in')}")
    result5 = change_email("user2@example.com", "final.user2@example.com", "securepass456")
    print(result5)
    print()

if __name__ == "__main__":
    main()