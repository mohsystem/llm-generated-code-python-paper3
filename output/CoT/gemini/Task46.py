import os
import hashlib
import re

# In-memory dictionary to act as a database
user_database = {}

MIN_PASSWORD_LENGTH = 8
# Regex for basic email validation
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

class User:
    def __init__(self, name, email, password_hash, salt):
        self.name = name
        self.email = email
        self.password_hash = password_hash
        self.salt = salt

    def __str__(self):
        return f"User(name='{self.name}', email='{self.email}')"

def hash_password(password, salt):
    """
    Hashes a password using PBKDF2 with a provided salt.
    NOTE: In a production environment, you might prefer Argon2, which requires an external library like 'argon2-cffi'.
    PBKDF2 is a secure, standard choice available in the standard library.
    """
    # Use PBKDF2 for key derivation
    # The number of iterations should be as high as your server can tolerate (e.g., 260,000 in 2022)
    iterations = 390000 
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return key

def register_user(name, email, password):
    """
    Registers a new user after validating the inputs.
    
    Args:
        name (str): The user's name.
        email (str): The user's email.
        password (str): The user's password.
        
    Returns:
        str: A message indicating the result of the registration attempt.
    """
    # 1. Input Validation
    if not name or not name.strip():
        return "Registration failed: Name cannot be empty."
    if not email or not EMAIL_REGEX.match(email):
        return "Registration failed: Invalid email format."
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"Registration failed: Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if email in user_database:
        return "Registration failed: Email already exists."

    # 2. Secure Password Handling
    salt = os.urandom(16)  # Generate a cryptographically secure salt
    password_hash = hash_password(password, salt)

    # 3. Store User Information
    new_user = User(name, email, password_hash, salt)
    user_database[email] = new_user

    return f"User '{name}' registered successfully."

def main():
    """Main function to run test cases."""
    print("--- User Registration System Test Cases ---")

    # Test Case 1: Successful registration
    print(f"1. {register_user('Alice Smith', 'alice@example.com', 'Password123!')}")

    # Test Case 2: Attempt to register with an existing email
    print(f"2. {register_user('Alice Jones', 'alice@example.com', 'AnotherPassword456')}")

    # Test Case 3: Attempt to register with an invalid email format
    print(f"3. {register_user('Bob Johnson', 'bob-at-invalid', 'SecurePass789')}")

    # Test Case 4: Attempt to register with a weak (short) password
    print(f"4. {register_user('Charlie Brown', 'charlie@example.com', 'pass')}")

    # Test Case 5: Attempt to register with an empty name
    print(f"5. {register_user('  ', 'david@example.com', 'ValidPassword101')}")

    # Print database contents (for verification)
    print("\nCurrent users in database:")
    for email, user in user_database.items():
        print(f"- {user}")

if __name__ == "__main__":
    main()