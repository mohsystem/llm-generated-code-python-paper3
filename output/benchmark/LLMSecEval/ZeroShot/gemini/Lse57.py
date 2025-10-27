# --- Data Structures to Simulate Database and Sessions ---

# Simulates a table of users. Format: {username: {'email': ..., 'hashed_password': ...}}
user_database = {}
# Simulates a unique index on email for fast lookups.
email_database = set()
# Simulates a set of currently active user sessions.
logged_in_users = set()


def hash_password(password: str) -> str:
    """
    A simple, insecure password hashing simulation.
    WARNING: Do NOT use this in production. Use a strong library like passlib with bcrypt.
    """
    if not password:
        return ""
    # Simple "hash" for demonstration: reverse the string and append a static "salt"
    return password[::-1] + "_hashed"


def setup_database():
    """Populates the simulated database with initial data."""
    global user_database, email_database, logged_in_users
    user_database.clear()
    email_database.clear()
    logged_in_users.clear()

    users = [
        {"username": "alice", "email": "alice@example.com", "password": "password123"},
        {"username": "bob", "email": "bob@example.com", "password": "bobpass"},
        {"username": "charlie", "email": "charlie@example.com", "password": "securepass"}
    ]

    for user in users:
        hashed = hash_password(user["password"])
        user_database[user["username"]] = {"email": user["email"], "hashed_password": hashed}
        email_database.add(user["email"])


def login(username: str, password: str) -> bool:
    """Simulates a user logging in."""
    user = user_database.get(username)
    if user and user["hashed_password"] == hash_password(password):
        logged_in_users.add(username)
        return True
    return False


def logout(username: str):
    """Simulates a user logging out."""
    logged_in_users.discard(username)


def change_email(logged_in_username: str, old_email: str, new_email: str, confirm_password: str) -> str:
    """
    Allows a logged-in user to change their email after confirming their identity.
    """
    # 1. Check if user is logged in
    if logged_in_username not in logged_in_users:
        return "Error: User is not logged in."

    # 2. Fetch user data
    user = user_database.get(logged_in_username)
    if not user:
        return "Error: User data not found for logged-in user."

    # 3. Verify old email matches records for this user
    if user["email"] != old_email:
        return "Error: The provided old email does not match our records."

    # 4. Verify password
    if user["hashed_password"] != hash_password(confirm_password):
        return "Error: Incorrect password."

    # 5. Validate new email
    if not new_email or "@" not in new_email:
        return "Error: New email format is invalid."
    if user["email"] == new_email:
        return "Error: New email cannot be the same as the old email."
    if new_email in email_database:
        return "Error: New email is already in use by another account."

    # 6. All checks passed, perform the update
    email_database.remove(user["email"])
    user["email"] = new_email
    email_database.add(new_email)

    return f"Success: Email has been changed to {new_email}"


if __name__ == "__main__":
    # Test Case 1: Successful email change
    print("--- Test Case 1: Successful Change ---")
    setup_database()
    login("alice", "password123")
    print(f"Alice's current info: {user_database.get('alice')}")
    result1 = change_email("alice", "alice@example.com", "alice_new@example.com", "password123")
    print(f"Result: {result1}")
    print(f"Alice's updated info: {user_database.get('alice')}")
    logout("alice")
    print()

    # Test Case 2: Failed change due to incorrect password
    print("--- Test Case 2: Incorrect Password ---")
    setup_database()
    login("bob", "bobpass")
    result2 = change_email("bob", "bob@example.com", "bob_new@example.com", "wrongpassword")
    print(f"Result: {result2}")
    print(f"Bob's info (should be unchanged): {user_database.get('bob')}")
    logout("bob")
    print()

    # Test Case 3: Failed change because user is not logged in
    print("--- Test Case 3: User Not Logged In ---")
    setup_database()
    # Note: No login call for charlie
    result3 = change_email("charlie", "charlie@example.com", "charlie_new@example.com", "securepass")
    print(f"Result: {result3}")
    print()

    # Test Case 4: Failed change because new email is already taken
    print("--- Test Case 4: New Email Already Exists ---")
    setup_database()
    login("alice", "password123")
    result4 = change_email("alice", "alice@example.com", "bob@example.com", "password123")
    print(f"Result: {result4}")
    logout("alice")
    print()

    # Test Case 5: Failed change due to incorrect old email provided
    print("--- Test Case 5: Incorrect Old Email Provided ---")
    setup_database()
    login("bob", "bobpass")
    result5 = change_email("bob", "wrong_old@example.com", "bob_new@example.com", "bobpass")
    print(f"Result: {result5}")
    logout("bob")
    print()