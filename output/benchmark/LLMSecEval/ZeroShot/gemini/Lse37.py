import hashlib
import hmac
import os

# Simulates a database table. In a real application, this would be a database.
# We store the user, their salt (bytes), and the salted+hashed password (hex).
# SECURITY NOTE: In a real application, use a stronger, adaptive hashing
# algorithm like Argon2 or BCrypt instead of a simple salted SHA-256.
USER_DATABASE = {}

def hash_password(password: str, salt: bytes) -> str:
    """Hashes a password with a salt using SHA-256."""
    # In Python 3, strings must be encoded to bytes before hashing.
    pwd_bytes = password.encode('utf-8')
    # Prepending salt to the password before hashing
    salted_password = salt + pwd_bytes
    hasher = hashlib.sha256()
    hasher.update(salted_password)
    return hasher.hexdigest()

def login(username: str, password: str) -> str:
    """
    Securely checks a user's credentials.
    Returns: "success", "cant_login", or "internal_server_error".
    """
    try:
        if not username or not password:
            return "cant_login"

        user_data = USER_DATABASE.get(username)
        
        if user_data is None:
            # To prevent timing attacks that could reveal if a username exists,
            # we perform a dummy hash and comparison.
            dummy_salt = os.urandom(16)
            dummy_hash = hash_password("dummy_password_for_timing_attack_prevention", dummy_salt)
            hmac.compare_digest(dummy_hash, "a") # Constant-time comparison
            return "cant_login"

        stored_salt = user_data['salt']
        stored_hash = user_data['hash']
        
        # Hash the provided password with the user's stored salt
        attempted_hash = hash_password(password, stored_salt)

        # Use a constant-time comparison to prevent timing attacks
        if hmac.compare_digest(attempted_hash, stored_hash):
            return "success"
        else:
            return "cant_login"

    except Exception as e:
        # Log the exception in a real application
        print(f"An unexpected error occurred: {e}")
        return "internal_server_error"

def setup_test_database():
    """Helper function to pre-populate the database for testing."""
    try:
        test_user = "alice"
        test_pass = "password123"

        # Generate a cryptographically secure random salt
        salt = os.urandom(16)
        
        # Hash the password with the salt
        hashed_pw = hash_password(test_pass, salt)

        # Store the credentials
        USER_DATABASE[test_user] = {'salt': salt, 'hash': hashed_pw}

        print(f"Test database setup for user: {test_user}")
        print(f"Salt (hex): {salt.hex()}")
        print(f"Hashed Password (hex): {hashed_pw}")
        print("------------------------------------")
    except Exception as e:
        print(f"Failed to setup test database: {e}")


if __name__ == '__main__':
    setup_test_database()

    # Test Cases
    print("Test Case 1: Correct credentials")
    result = login("alice", "password123")
    print(f"Login for 'alice' with 'password123': {result}\n")  # Expected: success

    print("Test Case 2: Correct username, incorrect password")
    result = login("alice", "wrongpassword")
    print(f"Login for 'alice' with 'wrongpassword': {result}\n")  # Expected: cant_login

    print("Test Case 3: Incorrect username")
    result = login("bob", "password123")
    print(f"Login for 'bob' with 'password123': {result}\n")  # Expected: cant_login

    print("Test Case 4: Empty password")
    result = login("alice", "")
    print(f"Login for 'alice' with '': {result}\n")  # Expected: cant_login
    
    print("Test Case 5: Empty username")
    result = login("", "password123")
    print(f"Login for '' with 'password123': {result}\n")  # Expected: cant_login