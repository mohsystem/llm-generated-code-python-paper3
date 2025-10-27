import hashlib
import os

# In-memory user database (simulated)
# In a real application, use a proper database (e.g., SQLite, PostgreSQL).
user_database = {}

def hash_password(password, salt):
    """Hashes a password with a given salt using SHA-256."""
    password_bytes = password.encode('utf-8')
    # Combine salt and password for hashing
    salted_password = salt + password_bytes
    # Hash the combined value
    hasher = hashlib.sha256()
    hasher.update(salted_password)
    return hasher.hexdigest()

def register_user(username, password):
    """
    Registers a new user by generating a salt, hashing the password,
    and storing the details.
    """
    if not username or not password:
        print("Error: Username and password cannot be empty.")
        return False
        
    if username in user_database:
        print(f"Registration failed: Username '{username}' already exists.")
        return False

    # Generate a cryptographically secure random salt
    salt = os.urandom(16)
    hashed_pwd = hash_password(password, salt)

    # Store the salt and hashed password
    # In a real DB, you'd store salt and hashed_pwd in separate columns
    user_database[username] = {
        'salt': salt.hex(),
        'hashed_password': hashed_pwd
    }
    print(f"User '{username}' registered successfully.")
    return True

if __name__ == "__main__":
    print("--- Running 5 Test Cases for User Registration ---")

    # Test Case 1: Successful registration
    print("\n[Test Case 1]")
    register_user("alice", "Password123!")

    # Test Case 2: Successful registration of another user
    print("\n[Test Case 2]")
    register_user("bob", "SecurePass@2023")

    # Test Case 3: Attempting to register a user that already exists
    print("\n[Test Case 3]")
    register_user("alice", "AnotherPassword")

    # Test Case 4: Registration with an empty username
    print("\n[Test Case 4]")
    register_user("", "some_password")
    
    # Test Case 5: Registration with a different password for a new user
    print("\n[Test Case 5]")
    register_user("charlie", "Password123!")

    # Optional: Print database state to verify
    print("\n--- Final Database State ---")
    import json
    print(json.dumps(user_database, indent=2))