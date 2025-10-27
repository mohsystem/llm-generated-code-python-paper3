import os
import hashlib
import hmac

# In-memory dictionary to simulate a user database.
# In a real application, this would be a database.
# The value for each user is a dictionary containing their salt and hashed password.
user_database = {}

ITERATIONS = 260000  # Recommended value by OWASP for PBKDF2-HMAC-SHA256
SALT_SIZE = 16
HASH_ALGORITHM = 'sha256'

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes the password using PBKDF2 with HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )

def register_user(username: str, password: str):
    """
    Registers a new user by hashing their password and storing it.
    This is a helper function to populate our simulated database.
    """
    if not username or not password:
        return
    salt = os.urandom(SALT_SIZE)
    hashed = hash_password(password, salt)
    user_database[username] = {
        'salt': salt,
        'hash': hashed
    }

def login(username: str, password: str) -> bool:
    """
    The main login function.
    
    Args:
        username: The username entered by the user.
        password: The password entered by the user.
        
    Returns:
        True for successful login, False otherwise.
    """
    if not username or not password:
        return False
        
    user_data = user_database.get(username)
    if user_data is None:
        # To prevent timing attacks, perform a dummy hash check to ensure
        # the execution time is similar for existing and non-existing users.
        hash_password(password, os.urandom(SALT_SIZE))
        print("Login failed: Username does not exist.")
        return False

    salt = user_data['salt']
    stored_hash = user_data['hash']
    
    # Hash the provided password with the user's stored salt
    provided_hash = hash_password(password, salt)
    
    # Compare hashes using a constant-time comparison function
    if hmac.compare_digest(stored_hash, provided_hash):
        print(f"Login successful for {username}. Redirecting to home page...")
        return True
    else:
        print("Login failed: Incorrect password.")
        return False

def main():
    """Main function to run test cases."""
    # Setup: Register users for testing
    register_user("admin", "P@ssword123!")
    register_user("user", "mySecurePass")
    
    print("--- Running Test Cases ---")
    
    # Test Case 1: Successful login
    print("\n[Test 1] Correct username and password:")
    login("admin", "P@ssword123!")
    
    # Test Case 2: Incorrect password
    print("\n[Test 2] Correct username, incorrect password:")
    login("admin", "WrongPassword")
    
    # Test Case 3: Non-existent username
    print("\n[Test 3] Non-existent username:")
    login("guest", "SomePassword")
    
    # Test Case 4: Empty password
    print("\n[Test 4] Correct username, empty password:")
    login("user", "")

    # Test Case 5: Case-sensitive username
    print("\n[Test 5] Case-sensitive username check (should fail):")
    login("Admin", "P@ssword123!")
    
    print("\n--- Test Cases Finished ---")


if __name__ == "__main__":
    main()