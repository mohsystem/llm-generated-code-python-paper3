import os
import hashlib
import re

# In-memory "database"
user_database = {}

# --- Security Constants ---
# Use a high iteration count as recommended by OWASP
PBKDF2_ITERATIONS = 260000
SALT_LENGTH_BYTES = 16
HASH_ALGORITHM = 'sha256'

# --- Validation Patterns ---
# A reasonably simple regex for email validation
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
# Password must be >= 8 chars, contain one uppercase, one lowercase, and one digit
PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")


def hash_password(password, salt):
    """Hashes password with a salt using PBKDF2."""
    if not isinstance(password, bytes):
        password = password.encode('utf-8')
    
    pwd_hash = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password,
        salt,
        PBKDF2_ITERATIONS
    )
    return pwd_hash.hex()

def generate_salt():
    """Generates a cryptographically secure random salt."""
    return os.urandom(SALT_LENGTH_BYTES)

def validate_input(name, email, password):
    """
    Validates user input.
    Returns None if valid, otherwise an error message string.
    """
    if not name or not 0 < len(name) <= 50:
        return "Invalid name. Must be between 1 and 50 characters."
    if not email or not EMAIL_REGEX.match(email):
        return "Invalid email format."
    if not password or not PASSWORD_REGEX.match(password):
        return "Password is too weak. Must be at least 8 characters, with one uppercase, one lowercase, and one number."
    return None

def register_user(name, email, password):
    """
    Registers a new user after validating and hashing credentials.
    Returns a tuple (success: bool, message: str).
    """
    error = validate_input(name, email, password)
    if error:
        return False, f"Registration failed: {error}"

    # Normalize email to be case-insensitive for uniqueness
    normalized_email = email.lower()

    if normalized_email in user_database:
        return False, f"Registration failed: Email '{email}' already exists."

    # Generate salt and hash password
    salt = generate_salt()
    hashed_pwd = hash_password(password, salt)

    # Store user data
    user_database[normalized_email] = {
        'name': name,
        'salt': salt.hex(),
        'hashed_password': hashed_pwd
    }
    
    return True, f"User '{name}' registered successfully."

# --- Main execution with test cases ---
def main():
    print("--- User Registration System ---")
    
    # Test Case 1: Successful registration
    success, message = register_user("Alice", "alice@example.com", "Password123")
    print(f"Test 1: {message}")

    # Test Case 2: Attempt to register with a duplicate email
    success, message = register_user("Alice Smith", "alice@example.com", "AnotherPass456")
    print(f"Test 2: {message}")

    # Test Case 3: Registration with an invalid email format
    success, message = register_user("Bob", "bob-at-example.com", "SecurePass789")
    print(f"Test 3: {message}")

    # Test Case 4: Registration with a weak password
    success, message = register_user("Charlie", "charlie@example.com", "pass")
    print(f"Test 4: {message}")

    # Test Case 5: Another successful registration
    success, message = register_user("David", "david@example.com", "MyP@ssw0rd!")
    print(f"Test 5: {message}")

    print("\n--- Current Database State ---")
    for email, data in user_database.items():
        print(f"Email: {email}, Data: {data}")

if __name__ == "__main__":
    main()