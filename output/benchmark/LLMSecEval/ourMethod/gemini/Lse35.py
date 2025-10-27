import hashlib
import os
import hmac
import re

# Simulate a user database
user_database = {}

# Cryptographic constants
SALT_LENGTH = 16
HASH_ALGORITHM = 'sha256'
# Per OWASP recommendation for PBKDF2-HMAC-SHA256
ITERATIONS = 210000

# Rule #1: Basic input validation regex
# Username: 3-20 chars, alphanumeric
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9]{3,20}$")
# Password: 8-64 chars, at least one letter and one digit
PASSWORD_REGEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,64}$")


def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes a password with a given salt using PBKDF2."""
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )
    return key


def register_user(username: str, password: str):
    """Registers a new user in the simulated database for setup."""
    if not isinstance(username, str) or not isinstance(password, str):
        print("Registration failed: Username and password must be strings.")
        return
        
    # Rule #9 & #10: Use a unique, cryptographically secure salt for each user
    salt = os.urandom(SALT_LENGTH)
    hashed_pass = hash_password(password, salt)
    
    user_database[username] = {
        'salt': salt,
        'hash': hashed_pass
    }
    print(f"User '{username}' registered.")


def login(username: str, password: str) -> str:
    """
    Simulates a login function.

    Args:
        username: The username from the form.
        password: The password from the form.
        
    Returns:
        A string indicating the page to redirect to: "HOME_PAGE" or "LOGIN_PAGE".
    """
    # Rule #1: Ensure all input is validated
    if not isinstance(username, str) or not USERNAME_REGEX.match(username):
        print("Error: Invalid username format.", flush=True)
        return "LOGIN_PAGE"
        
    if not isinstance(password, str) or not PASSWORD_REGEX.match(password):
        print("Error: Invalid password format.", flush=True)
        return "LOGIN_PAGE"

    user_data = user_database.get(username)
    if user_data is None:
        # To prevent timing attacks for username enumeration,
        # perform a dummy hash calculation.
        hash_password("dummy_password", os.urandom(SALT_LENGTH))
        return "LOGIN_PAGE"
        
    stored_hash = user_data['hash']
    salt = user_data['salt']
    
    # Hash the provided password with the user's stored salt
    provided_hash = hash_password(password, salt)
    
    # Rule #7 & #8: Use a vetted library and constant-time comparison
    if hmac.compare_digest(stored_hash, provided_hash):
        return "HOME_PAGE"
    else:
        return "LOGIN_PAGE"


if __name__ == '__main__':
    # Populate the mock database for demonstration
    register_user("admin", "AdminPass123")
    register_user("user1", "UserPass456")

    print("\n--- Running Test Cases ---")
    
    # Test Case 1: Successful login
    print("\nTest Case 1: Valid credentials for 'admin'")
    result1 = login("admin", "AdminPass123")
    print(f"Result: Login {'successful' if result1 == 'HOME_PAGE' else 'failed'}. Redirecting to {result1}")
    
    # Test Case 2: Incorrect password
    print("\nTest Case 2: Invalid password for 'admin'")
    result2 = login("admin", "WrongPass789")
    print(f"Result: Login {'successful' if result2 == 'HOME_PAGE' else 'failed'}. Redirecting to {result2}")
    
    # Test Case 3: Non-existent user
    print("\nTest Case 3: Non-existent user 'nouser'")
    result3 = login("nouser", "SomePass123")
    print(f"Result: Login {'successful' if result3 == 'HOME_PAGE' else 'failed'}. Redirecting to {result3}")

    # Test Case 4: Invalid username format
    print("\nTest Case 4: Invalid username format 'us'")
    result4 = login("us", "SomePass123")
    print(f"Result: Login {'successful' if result4 == 'HOME_PAGE' else 'failed'}. Redirecting to {result4}")

    # Test Case 5: Invalid password format (too short)
    print("\nTest Case 5: Invalid password format for 'user1'")
    result5 = login("user1", "pass")
    print(f"Result: Login {'successful' if result5 == 'HOME_PAGE' else 'failed'}. Redirecting to {result5}")