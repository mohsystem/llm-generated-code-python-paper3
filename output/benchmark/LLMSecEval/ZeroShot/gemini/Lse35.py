import hashlib
import os
import base64
import hmac

# A mock database storing: username -> salt:hashedPassword
user_database = {}

# Use a strong algorithm like PBKDF2.
# Parameters should be tuned for your system's performance.
ITERATIONS = 65536
KEY_LENGTH = 32  # 32 bytes = 256 bits for SHA-256
SALT_LENGTH = 16 # 16 bytes = 128 bits
HASH_ALGORITHM = 'sha256'

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes the password using PBKDF2 with the given salt."""
    if not isinstance(password, str) or not isinstance(salt, bytes):
        raise TypeError("Password must be a string and salt must be bytes.")
    
    # Use password.encode('utf-8') to convert the string to bytes
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    return key

def register_user(username: str, password: str):
    """Registers a new user by hashing their password and storing it."""
    if not username or not password:
        return # Do not register users with empty credentials

    # Generate a cryptographically secure random salt
    salt = os.urandom(SALT_LENGTH)
    hashed_pass = hash_password(password, salt)
    
    # Store salt and hash together, encoded as Base64 strings
    encoded_salt = base64.b64encode(salt).decode('utf-8')
    encoded_hash = base64.b64encode(hashed_pass).decode('utf-8')
    
    user_database[username] = f"{encoded_salt}:{encoded_hash}"

def login(username: str, password: str) -> bool:
    """
    Simulates a login attempt.
    Returns True for success, False for failure.
    """
    if not username or not password:
        return False

    stored_data = user_database.get(username)
    if not stored_data:
        # To prevent timing attacks, perform a dummy hash even if the user doesn't exist.
        hash_password("dummy_password", os.urandom(SALT_LENGTH))
        return False
        
    try:
        encoded_salt, stored_encoded_hash = stored_data.split(':')
        
        salt = base64.b64decode(encoded_salt)
        stored_hash = base64.b64decode(stored_encoded_hash)
        
        # Hash the provided password with the stored salt
        provided_password_hash = hash_password(password, salt)

        # Use hmac.compare_digest for a constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_hash, provided_password_hash)

    except (ValueError, TypeError):
        # Handle potential errors with stored data format
        return False

def main():
    """Main function to run test cases."""
    # Setup: Register some users in our mock database
    register_user("admin", "S3cureP@ssword123!")
    register_user("user1", "myWeakPassword")

    print("--- Running 5 Test Cases ---")

    # Test Case 1: Successful login for admin
    test1 = login("admin", "S3cureP@ssword123!")
    print(f"Test 1 (Correct admin password): {'SUCCESS -> Redirect to home page' if test1 else 'FAIL -> Redirect to login page'}")

    # Test Case 2: Failed login for admin (wrong password)
    test2 = login("admin", "wrongpassword")
    print(f"Test 2 (Incorrect admin password): {'SUCCESS -> Redirect to home page' if test2 else 'FAIL -> Redirect to login page'}")

    # Test Case 3: Failed login for non-existent user
    test3 = login("nonexistentuser", "somepassword")
    print(f"Test 3 (Non-existent user): {'SUCCESS -> Redirect to home page' if test3 else 'FAIL -> Redirect to login page'}")

    # Test Case 4: Successful login for another user
    test4 = login("user1", "myWeakPassword")
    print(f"Test 4 (Correct user1 password): {'SUCCESS -> Redirect to home page' if test4 else 'FAIL -> Redirect to login page'}")

    # Test Case 5: Failed login with empty credentials
    test5 = login("", "S3cureP@ssword123!")
    print(f"Test 5 (Empty username): {'SUCCESS -> Redirect to home page' if test5 else 'FAIL -> Redirect to login page'}")

if __name__ == "__main__":
    main()