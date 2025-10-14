import hashlib
import secrets
import base64
import os

# Configuration constants
# Use a high iteration count as recommended by OWASP
ITERATIONS = 210000
# Key length in bytes for SHA-256
KEY_LENGTH_BYTES = 32
SALT_LENGTH_BYTES = 16
MIN_PASSWORD_LENGTH = 8

# In-memory user store for demonstration
user_database = {}

def hash_password(password: str) -> str | None:
    """
    Hashes a password using PBKDF2-HMAC-SHA256.

    Args:
        password: The plaintext password.

    Returns:
        A formatted string containing algorithm, iterations, salt, and hash,
        or None if the password is too short.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        print("Error: Password does not meet the length requirement.")
        return None
    
    salt = secrets.token_bytes(SALT_LENGTH_BYTES)
    
    # Use PBKDF2-HMAC with SHA-256
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH_BYTES
    )
    
    # Encode salt and hash to Base64 for safe storage
    salt_b64 = base64.b64encode(salt).decode('ascii')
    key_b64 = base64.b64encode(key).decode('ascii')
    
    # Format according to a common standard
    return f"$pbkdf2-sha256${ITERATIONS}${salt_b64}${key_b64}"

def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a password against a stored hash string.

    Args:
        password: The plaintext password to check.
        stored_hash: The hash string from hash_password.

    Returns:
        True if the password matches, False otherwise.
    """
    try:
        # Parse the stored hash string
        parts = stored_hash.split('$')
        if len(parts) != 5:
            return False
        
        algorithm_info, iterations_str, salt_b64, key_b64 = parts[1:]
        
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64)
        stored_key = base64.b64decode(key_b64)
        
        # Re-compute the hash with the same parameters
        comparison_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations,
            dklen=KEY_LENGTH_BYTES
        )
        
        # Use secrets.compare_digest for constant-time comparison
        return secrets.compare_digest(stored_key, comparison_key)

    except (ValueError, IndexError, TypeError):
        # Malformed hash string or encoding error
        return False

def sign_up(username: str, password: str):
    """Simulates a user signup process."""
    print(f"Attempting to sign up user: {username}")
    hashed_password = hash_password(password)
    if hashed_password:
        user_database[username] = hashed_password
        print(f"User '{username}' signed up successfully.")
    else:
        print(f"Signup for user '{username}' failed.")

def login(username: str, password: str):
    """Simulates a user login process."""
    print(f"Attempting to log in user: {username}")
    stored_hash = user_database.get(username)
    if not stored_hash:
        print("Login failed: User not found.")
        return

    if verify_password(password, stored_hash):
        print(f"Login successful for user '{username}'.")
    else:
        print("Login failed: Incorrect password.")

def main():
    """Main function with test cases."""
    # Test Case 1: Successful signup and login
    print("--- Test Case 1 ---")
    user1 = "alice"
    pass1 = "Str0ngP@ssw0rd1"
    sign_up(user1, pass1)
    login(user1, pass1)
    print()

    # Test Case 2: Login with incorrect password
    print("--- Test Case 2 ---")
    wrong_pass1 = "WrongPassword!_"
    login(user1, wrong_pass1)
    print()

    # Test Case 3: Signup with a weak (short) password
    print("--- Test Case 3 ---")
    user2 = "bob"
    pass2_weak = "short"
    sign_up(user2, pass2_weak)
    print()

    # Test Case 4: Successful signup for a second user
    print("--- Test Case 4 ---")
    user3 = "charlie"
    pass3 = "An0th3rS3curePwd"
    sign_up(user3, pass3)
    login(user3, pass3)
    print()

    # Test Case 5: Attempt to log in a non-existent user
    print("--- Test Case 5 ---")
    login("david", "SomePassword123")
    print()

if __name__ == "__main__":
    main()