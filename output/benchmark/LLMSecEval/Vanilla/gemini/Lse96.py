import hashlib
import os

# Simulate a user database (username: stored_value)
user_database = {}

def generate_salt(length=16):
    """
    Generates a cryptographically secure salt.
    :param length: The length of the salt in bytes.
    :return: A byte string representing the salt.
    """
    return os.urandom(length)

def hash_password(password, salt):
    """
    Hashes a password with the given salt using SHA-256.
    :param password: The password string to hash.
    :param salt: The salt (bytes) to use for hashing.
    :return: The hexadecimal string of the hashed password.
    """
    password_bytes = password.encode('utf-8')
    # Combine salt and password before hashing
    salted_password = salt + password_bytes
    hasher = hashlib.sha256(salted_password)
    return hasher.hexdigest()

def register_user(username, password):
    """
    Registers a new user by generating a salt, hashing the password,
    and storing the result in the simulated database.
    :param username: The username for the new user.
    :param password: The password for the new user.
    :return: The stored value (salt + hashed_password) or an error message.
    """
    if username in user_database:
        return "Error: Username already exists."
    if not password:
        return "Error: Password cannot be empty."

    salt_bytes = generate_salt()
    hashed_pwd = hash_password(password, salt_bytes)
    
    # Get hex representation of salt for storage
    salt_hex = salt_bytes.hex()
    
    # Concatenate hex salt and hashed password for storage
    stored_value = salt_hex + hashed_pwd
    user_database[username] = stored_value
    
    return stored_value

def main():
    """Main function with 5 test cases."""
    print("--- Python Registration Simulation ---")
    
    # Test Case 1
    print("\n1) Registering user 'alice'...")
    alice_data = register_user("alice", "password123")
    print(f"   Stored data for alice: {alice_data}")

    # Test Case 2
    print("\n2) Registering user 'bob'...")
    bob_data = register_user("bob", "mySecret!@#")
    print(f"   Stored data for bob: {bob_data}")

    # Test Case 3
    print("\n3) Registering user 'charlie'...")
    charlie_data = register_user("charlie", "P@ssw0rd_")
    print(f"   Stored data for charlie: {charlie_data}")

    # Test Case 4
    print("\n4) Attempting to register 'alice' again...")
    alice_duplicate_data = register_user("alice", "anotherPassword")
    print(f"   Result: {alice_duplicate_data}")
    
    # Test Case 5
    print("\n5) Registering user 'dave'...")
    dave_data = register_user("dave", "davespassword")
    print(f"   Stored data for dave: {dave_data}")
    
    print("\n--- Final Database State ---")
    for username, stored_data in user_database.items():
        print(f"User: {username}, Stored: {stored_data}")


if __name__ == "__main__":
    main()