import hashlib
import os
import secrets

# In a real application, this would be a database.
user_database = {}

ITERATIONS = 600000
KEY_LENGTH = 32  # 256 bits
ALGORITHM = 'sha256'

def setup_database():
    """Utility to pre-populate the database for the example."""
    try:
        username = "admin"
        password = "password123"
        # Rule #9 & #10: Use a cryptographically secure random generator for a unique salt
        salt = secrets.token_bytes(16)
        
        # Rule #8: Use PBKDF2 for key derivation (password hashing)
        hashed_password = hashlib.pbkdf2_hmac(ALGORITHM, password.encode('utf-8'), salt, ITERATIONS, dklen=KEY_LENGTH)
        
        user_database[username] = {
            'salt': salt,
            'hashed_password': hashed_password
        }
        
        # Add a user to trigger a simulated error (e.g., corrupted data)
        user_database["error_user"] = None
        
    except Exception:
        # In a real app, this would be a fatal startup error.
        print("Error: Could not set up the user database.")
        exit(1)


def login(username, password):
    """
    Checks if the username and password are valid.
    Returns 'success', 'cant_login', or 'internal_server_error'.
    """
    try:
        # Rule #1: Input Validation
        if not username or not password or not isinstance(username, str) or not isinstance(password, str):
            return "cant_login"

        # To prevent DoS with overly long inputs
        if len(username) > 100 or len(password) > 100:
            return "cant_login"

        # User lookup
        credentials = user_database.get(username)
        if not credentials:
             # To prevent username enumeration via timing analysis, a real system
             # would perform a dummy hash calculation here against a dummy hash.
            return "cant_login"

        # Simulating an internal error case (e.g., corrupted data)
        if 'salt' not in credentials or 'hashed_password' not in credentials:
            raise ValueError(f"User data is corrupted for user: {username}")
        
        salt = credentials['salt']
        stored_hashed_password = credentials['hashed_password']

        # Hash the provided password with the stored salt
        provided_password_hash = hashlib.pbkdf2_hmac(
            ALGORITHM,
            password.encode('utf-8'),
            salt,
            ITERATIONS,
            dklen=KEY_LENGTH
        )
        
        # Rule #16: Use constant-time comparison to prevent timing attacks
        if secrets.compare_digest(stored_hashed_password, provided_password_hash):
            return "success"
        else:
            return "cant_login"
            
    # Rule #15: Ensure that all exceptions are caught and handled
    except Exception:
        # In a real app, log the error securely without exposing details to the user.
        return "internal_server_error"

def main():
    """Main function with test cases."""
    setup_database()
    
    print("--- 5 Test Cases ---")

    # 1. Correct login
    result1 = login("admin", "password123")
    print(f"Test 1 (Correct login): {result1}")

    # 2. Incorrect password
    result2 = login("admin", "wrongpassword")
    print(f"Test 2 (Incorrect password): {result2}")

    # 3. Incorrect username
    result3 = login("unknownuser", "password123")
    print(f"Test 3 (Incorrect username): {result3}")

    # 4. Empty/null input
    result4 = login("", "")
    print(f"Test 4 (Empty input): {result4}")

    # 5. Internal error simulation
    result5 = login("error_user", "any_password")
    print(f"Test 5 (Internal error simulation): {result5}")

if __name__ == "__main__":
    main()