import hashlib
import os

# In-memory dictionary to act as a database
database = {}

def hash_password(password):
    """
    Hashes a password with a random salt using SHA-256.
    In a real-world application, use a stronger key derivation function like Argon2 or bcrypt.
    
    :param password: The password string to hash.
    :return: A string containing the salt and hash, separated by a colon.
    """
    # Generate a random salt
    salt = os.urandom(16)
    
    # Hash the password with the salt
    # The password must be encoded to bytes before hashing
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    
    # Store salt and hash as hex strings
    salt_hex = salt.hex()
    pwd_hash_hex = pwd_hash.hex()
    
    return f"{salt_hex}:{pwd_hash_hex}"

def register_user(username, password, first_name, last_name, email):
    """
    Registers a new user by checking for username existence and storing details.
    
    :param username: The username for the new account.
    :param password: The password for the new account.
    :param first_name: The user's first name.
    :param last_name: The user's last name.
    :param email: The user's email address.
    :return: A status message string.
    """
    # Input validation
    if not username or not password:
        return "Registration failed: Username and password cannot be empty."

    # Check if the username already exists in the database
    if username in database:
        return f"Registration failed: Username '{username}' already exists."
    
    # Hash the password for secure storage
    hashed_password = hash_password(password)
    
    # Store the new user's information
    database[username] = {
        'hashed_password': hashed_password,
        'first_name': first_name,
        'last_name': last_name,
        'email': email
    }
    
    return f"Registration for '{username}' succeeded."

# Main execution block with test cases
if __name__ == "__main__":
    print("--- User Registration System ---")
    
    # Test Case 1: Successful registration
    result1 = register_user("jdoe", "Password123", "John", "Doe", "jdoe@example.com")
    print(f"Test Case 1: {result1}")

    # Test Case 2: Attempt to register with an existing username
    result2 = register_user("jdoe", "AnotherPass", "Jane", "Doe", "jane.d@example.com")
    print(f"Test Case 2: {result2}")
    
    # Test Case 3: Successful registration for another user
    result3 = register_user("asmith", "SecureP@ss!", "Alice", "Smith", "asmith@example.com")
    print(f"Test Case 3: {result3}")

    # Test Case 4: Registration with an empty username
    result4 = register_user("", "MyPassword", "Bob", "White", "bwhite@example.com")
    print(f"Test Case 4: {result4}")

    # Test Case 5: Another successful registration
    result5 = register_user("cgreen", "MyP@ssw0rd", "Charlie", "Green", "cgreen@example.com")
    print(f"Test Case 5: {result5}")

    # Print database state for verification
    print("\nCurrent database state:")
    for username, data in database.items():
        print(f"Username: {username}, Hashed Password: {data['hashed_password']}")