import hashlib
import re
import secrets
import os

# Using an in-memory dictionary to simulate a database
user_database = {}

# Strong password policy: min 12 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char.
PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

HASH_ITERATIONS = 210000
SALT_SIZE = 16
HASH_ALGORITHM = 'sha256'

def hash_password(password, salt):
    """Hashes the password with the given salt using PBKDF2-HMAC."""
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        HASH_ITERATIONS,
        dklen=32  # 256 bits
    )
    return key

def register_user(username, password, first_name, last_name, email):
    """
    Registers a new user after validating input and checking for username existence.
    """
    if not (username and isinstance(username, str) and USERNAME_REGEX.match(username)):
        return "Registration failed: Invalid username format. Must be 3-20 alphanumeric characters or underscores."

    if not (password and isinstance(password, str) and PASSWORD_REGEX.match(password)):
        return "Registration failed: Password does not meet policy. Must be at least 12 characters and contain an uppercase letter, a lowercase letter, a digit, and a special character."

    if not (first_name and isinstance(first_name, str) and 1 <= len(first_name) <= 50):
        return "Registration failed: Invalid first name."

    if not (last_name and isinstance(last_name, str) and 1 <= len(last_name) <= 50):
        return "Registration failed: Invalid last name."

    if not (email and isinstance(email, str) and EMAIL_REGEX.match(email)):
        return "Registration failed: Invalid email format."

    if username in user_database:
        return f"Registration failed: Username '{username}' already exists."

    try:
        salt = secrets.token_bytes(SALT_SIZE)
        hashed_password = hash_password(password, salt)

        user_database[username] = {
            'salt': salt.hex(),
            'hashed_password': hashed_password.hex(),
            'first_name': first_name,
            'last_name': last_name,
            'email': email
        }
        return f"Registration succeeded for username: {username}"
    finally:
        # The password variable goes out of scope and is garbage collected.
        # Explicit clearing is not as straightforward in Python as in C/Java.
        password = None


def main():
    """Main function with test cases."""
    print("--- Running Test Cases ---")
    
    # Test Case 1: Successful Registration
    print("Test 1:", register_user("john_doe", "StrongPass@123", "John", "Doe", "john.doe@example.com"))

    # Test Case 2: Username already exists
    print("Test 2:", register_user("john_doe", "AnotherPass@456", "John", "Doe", "john.d@example.com"))

    # Test Case 3: Weak password (too short)
    print("Test 3:", register_user("jane_doe", "Weak1@", "Jane", "Doe", "jane.doe@example.com"))

    # Test Case 4: Invalid username (too short)
    print("Test 4:", register_user("jd", "StrongPass@123", "Jane", "Doe", "jane.doe@example.com"))

    # Test Case 5: Invalid email
    print("Test 5:", register_user("peter_jones", "StrongPass@123", "Peter", "Jones", "peterjones@invalid"))

    print("\n--- Database Content (for verification) ---")
    for username, data in user_database.items():
        print(f"Username: {username}, Hashed Password: {data['hashed_password'][:10]}...")

if __name__ == "__main__":
    main()