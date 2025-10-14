# Simulates a user database
user_database = {}

def reset_password(db, username, new_password):
    """
    Resets the password for a given user if the user exists.

    Args:
        db (dict): The user database (dictionary of username: password).
        username (str): The username of the user.
        new_password (str): The new password to set.

    Returns:
        bool: True if the password was successfully reset, False otherwise.
    """
    if not username:
        return False
        
    if username in db:
        db[username] = new_password
        return True
    return False

def main():
    # Initialize the database with some users
    global user_database
    user_database = {
        "alice": "password123",
        "bob": "bobspass",
        "charlie": "securepass"
    }

    print(f"Initial Database: {user_database}")
    print("--- Running Test Cases ---")

    # Test Case 1: Successful password reset for an existing user
    result1 = reset_password(user_database, "alice", "newAlicePass!@#")
    print(f"1. Resetting 'alice' password. Success: {result1}")
    print(f"   Database after: {user_database}")

    # Test Case 2: Attempt to reset password for a non-existent user
    result2 = reset_password(user_database, "dave", "davespass")
    print(f"\n2. Resetting 'dave' (non-existent) password. Success: {result2}")
    print(f"   Database after: {user_database}")

    # Test Case 3: Successful reset for another existing user
    result3 = reset_password(user_database, "bob", "betterP@ssw0rd")
    print(f"\n3. Resetting 'bob' password. Success: {result3}")
    print(f"   Database after: {user_database}")

    # Test Case 4: Resetting the same user's password again
    result4 = reset_password(user_database, "alice", "evenNewerPass456")
    print(f"\n4. Resetting 'alice' password again. Success: {result4}")
    print(f"   Database after: {user_database}")

    # Test Case 5: Attempt to reset password with an empty username
    result5 = reset_password(user_database, "", "somepassword")
    print(f"\n5. Resetting password for empty username. Success: {result5}")
    print(f"   Database after: {user_database}")

if __name__ == "__main__":
    main()