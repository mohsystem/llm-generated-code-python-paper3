import os
import hashlib
import re
from secrets import token_bytes, compare_digest

# In a real application, this would be a database.
USER_DATABASE = {}

# Strong password policy: at least 8 chars, one uppercase, one lowercase, one digit, one special char.
PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")

# Username policy: 5-20 alphanumeric characters
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9]{5,20}$")

SALT_LENGTH = 16
ITERATIONS = 260000  # Recommended by OWASP as of 2023 for PBKDF2-HMAC-SHA256
HASH_ALGORITHM = 'sha256'

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes the password with the given salt using PBKDF2."""
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )
    return key

def register_user(username: str, password: str) -> bool:
    """Registers a new user with a securely hashed password."""
    if not isinstance(username, str) or not isinstance(password, str):
        print("Registration failed: Invalid input types.")
        return False
        
    if not USERNAME_REGEX.match(username) or not PASSWORD_REGEX.match(password):
        print("Registration failed: Username or password does not meet complexity requirements.")
        return False

    if username in USER_DATABASE:
        print(f"Registration failed: Username '{username}' already exists.")
        return False

    salt = token_bytes(SALT_LENGTH)
    password_hash = hash_password(password, salt)
    
    # Store salt and hash (in a real app, salt and hash would be stored as bytes or hex strings)
    USER_DATABASE[username] = {'salt': salt, 'hash': password_hash}
    print(f"User '{username}' registered successfully.")
    return True

def login(username: str, password: str) -> bool:
    """Authenticates a user by checking their username and password."""
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        print("Login failed: Username or password cannot be empty.")
        # Simulating redirect to login page
        return False
        
    user_data = USER_DATABASE.get(username)
    if not user_data:
        print("Login failed: Incorrect username or password.") # Generic message
        # Simulating redirect to login page
        return False

    salt = user_data['salt']
    stored_hash = user_data['hash']
    
    attempted_hash = hash_password(password, salt)
    
    # Use compare_digest for constant-time comparison to prevent timing attacks
    if compare_digest(stored_hash, attempted_hash):
        print(f"Login successful for user '{username}'. Redirecting to dashboard.")
        # Simulating redirect to dashboard
        return True
    else:
        print("Login failed: Incorrect username or password.")
        # Simulating redirect to login page
        return False

def main():
    """Main function with test cases."""
    print("--- Setting up user ---")
    register_user("testuser1", "StrongPass@2024")
    print("\n--- Running Test Cases ---")

    # Test Case 1: Correct username and password
    print("1. Testing correct credentials...")
    login("testuser1", "StrongPass@2024")

    # Test Case 2: Correct username, incorrect password
    print("\n2. Testing incorrect password...")
    login("testuser1", "WrongPassword!1")

    # Test Case 3: Incorrect username
    print("\n3. Testing incorrect username...")
    login("nonexistentuser", "StrongPass@2024")
    
    # Test Case 4: Empty password
    print("\n4. Testing empty password...")
    login("testuser1", "")

    # Test Case 5: Registration with weak password
    print("\n5. Testing registration with weak password...")
    register_user("weakuser", "pass")

if __name__ == "__main__":
    main()