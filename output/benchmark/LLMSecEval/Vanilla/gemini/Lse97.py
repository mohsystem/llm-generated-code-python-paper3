import hashlib

# In-memory dictionary to simulate a database
database = {}

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def register_user(username, password, first_name, last_name, email):
    """
    Registers a new user.
    Checks if the username exists, hashes the password, and stores the user.
    Returns a message indicating success or failure.
    """
    if username in database:
        return f"Username '{username}' already exists."
    else:
        hashed_password = hash_password(password)
        database[username] = {
            'hashed_password': hashed_password,
            'first_name': first_name,
            'last_name': last_name,
            'email': email
        }
        return f"Registration succeeded for username '{username}'."

def main():
    """Main function with 5 test cases."""
    # --- Test Cases ---

    # Test Case 1: Successful registration
    result1 = register_user("jdoe", "Password123", "John", "Doe", "jdoe@example.com")
    print(f"Test Case 1: {result1}")

    # Test Case 2: Another successful registration
    result2 = register_user("asmith", "SecurePass!", "Alice", "Smith", "asmith@example.com")
    print(f"Test Case 2: {result2}")

    # Test Case 3: Attempt to register with an existing username
    result3 = register_user("jdoe", "AnotherPass", "Jane", "Doe", "jane.d@example.com")
    print(f"Test Case 3: {result3}")

    # Test Case 4: A third successful registration
    result4 = register_user("peterpan", "neverland", "Peter", "Pan", "peter.p@example.com")
    print(f"Test Case 4: {result4}")

    # Test Case 5: Another failed registration with a duplicate username
    result5 = register_user("asmith", "MyPass123", "Adam", "Smithy", "a.smith@example.com")
    print(f"Test Case 5: {result5}")

    # Optional: Print the database content to verify
    # import json
    # print("\nCurrent database state:")
    # print(json.dumps(database, indent=2))

if __name__ == "__main__":
    main()