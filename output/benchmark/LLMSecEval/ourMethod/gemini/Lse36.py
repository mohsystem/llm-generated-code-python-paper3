import hashlib
import hmac
import os
import secrets

# In a real application, this would be a database.
_user_database = {}

# Strong cryptographic parameters
_SALT_BYTES = 16
_HASH_ALGORITHM = 'sha256'
_ITERATIONS = 390000

class User:
    """Represents a user record in the database."""
    def __init__(self, salt: bytes, hashed_password: bytes):
        self.salt = salt
        self.hashed_password = hashed_password

def _hash_password(password: str, salt: bytes) -> bytes:
    """Hashes a password with a given salt using PBKDF2-HMAC."""
    password_bytes = password.encode('utf-8')
    key = hashlib.pbkdf2_hmac(
        _HASH_ALGORITHM,
        password_bytes,
        salt,
        _ITERATIONS
    )
    # Securely clear sensitive data if possible (in CPython it's harder)
    # The original password_bytes will be garbage collected.
    return key

def register_user(username: str, password: str):
    """
    Registers a new user. In a real application, this would store the user in a database.
    This is a helper for setting up test cases.
    """
    if not username or not password:
        print("Registration failed: Username and password cannot be empty.")
        return
    
    salt = secrets.token_bytes(_SALT_BYTES)
    hashed_password = _hash_password(password, salt)
    _user_database[username] = User(salt, hashed_password)
    print(f"User '{username}' registered successfully.")

def login(username: str, password: str) -> bool:
    """
    Simulates a user login process.
    
    Args:
        username: The username provided by the user.
        password: The password provided by the user.
        
    Returns:
        True if login is successful, False otherwise.
    """
    # 1. Input validation
    if not username or not password:
        print("Login failed: Username and password cannot be empty.")
        return False

    # 2. Query database for username
    user = _user_database.get(username)
    if user is None:
        # To prevent username enumeration, we can perform a dummy hash
        # This makes the response time similar for existing and non-existing users.
        _hash_password("dummy_password_for_timing", secrets.token_bytes(_SALT_BYTES))
        print("Login failed: Invalid username or password.")
        return False
        
    # 3. Hash the provided password with the user's stored salt
    provided_password_hash = _hash_password(password, user.salt)
    
    # 4. Compare hashes in constant time to prevent timing attacks
    password_correct = hmac.compare_digest(provided_password_hash, user.hashed_password)
    
    if password_correct:
        print(f"Login successful for user '{username}'. Redirecting to home page...")
        return True
    else:
        print("Login failed: Invalid username or password.")
        return False

def main():
    """Main function to run test cases."""
    # Setup: Register some users for testing
    register_user("alice", "Password123!")
    register_user("bob", "SecurePass@2024")

    print("\n--- Running Test Cases ---")

    # Test Case 1: Successful login
    print("\n[Test 1] Correct credentials for 'alice'")
    login("alice", "Password123!")

    # Test Case 2: Incorrect password
    print("\n[Test 2] Incorrect password for 'alice'")
    login("alice", "wrongpassword")

    # Test Case 3: Non-existent user
    print("\n[Test 3] Non-existent user 'charlie'")
    login("charlie", "anypassword")

    # Test Case 4: Successful login for another user
    print("\n[Test 4] Correct credentials for 'bob'")
    login("bob", "SecurePass@2024")
    
    # Test Case 5: Empty username
    print("\n[Test 5] Empty username")
    login("", "somepassword")

if __name__ == "__main__":
    main()