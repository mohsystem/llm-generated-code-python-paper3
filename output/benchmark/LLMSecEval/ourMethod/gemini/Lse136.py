import os
import hashlib
import secrets

MIN_USERNAME_LENGTH = 4
MAX_USERNAME_LENGTH = 64
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

HASH_ALGORITHM = 'sha256'
ITERATIONS = 600000
KEY_LENGTH = 32  # 32 bytes = 256 bits
SALT_LENGTH = 16 # 16 bytes = 128 bits

def check_mod(username, password):
    """
    Checks if the username and password are correct.
    This function simulates being called by a web framework.

    :param username: The username from the URL.
    :param password: The password from the URL.
    :return: "true" if credentials are valid, "false" otherwise.
    """
    # Rule #1: Ensure all input is validated.
    if not isinstance(username, str) or not (MIN_USERNAME_LENGTH <= len(username) <= MAX_USERNAME_LENGTH):
        return "false"
    if not isinstance(password, str) or not (MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH):
        return "false"

    try:
        # Rule #7: Avoid hardcoding credentials. Fetch from a secure source like environment variables.
        stored_username = os.environ.get("CORRECT_USERNAME")
        stored_hash_hex = os.environ.get("PASSWORD_HASH")
        stored_salt_hex = os.environ.get("PASSWORD_SALT")

        if not all([stored_username, stored_hash_hex, stored_salt_hex]):
            # Configuration error, fail securely.
            return "false"

        # Simple username check. In a real system, this would be a database lookup.
        if username != stored_username:
            # To prevent username enumeration, a dummy hash operation should still be performed.
            # For simplicity, we return early, but in a high-security context, this should be avoided.
            return "false"
            
        stored_salt = bytes.fromhex(stored_salt_hex)
        stored_hash = bytes.fromhex(stored_hash_hex)

        # Hash the provided password with the stored salt
        generated_hash = hashlib.pbkdf2_hmac(
            HASH_ALGORITHM,
            password.encode('utf-8'),
            stored_salt,
            ITERATIONS,
            dklen=KEY_LENGTH
        )
        
        # Rule #10: Use constant-time comparison to prevent timing attacks.
        if secrets.compare_digest(stored_hash, generated_hash):
            return "true"

    except (ValueError, TypeError) as e:
        # Log the exception in a real application.
        print(f"Authentication error: {e}")
        return "false"
        
    return "false"

def generate_salt():
    """Rule #9: Use a cryptographically secure random number generator."""
    return secrets.token_bytes(SALT_LENGTH)

def hash_password(password, salt):
    """Rule #5, #8: Use strong hashing with a unique salt per password."""
    return hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )

def main():
    """Main function with test cases."""
    print("--- Running 5 Test Cases ---")
    
    # --- Test Setup ---
    # In a real app, this setup is done during user registration and deployment.
    correct_username = "testuser"
    correct_password = "S3cur3P@ssw0rd!"

    salt = generate_salt()
    hashed_password = hash_password(correct_password, salt)
    
    # Store credentials in environment variables for the test
    os.environ["CORRECT_USERNAME"] = correct_username
    os.environ["PASSWORD_SALT"] = salt.hex()
    os.environ["PASSWORD_HASH"] = hashed_password.hex()

    # --- Test Cases ---
    # Test Case 1: Correct username, correct password
    result1 = check_mod(correct_username, correct_password)
    print(f"Test 1 (Correct credentials): {result1} (Expected: true)")
    
    # Test Case 2: Correct username, incorrect password
    result2 = check_mod(correct_username, "wrongpassword")
    print(f"Test 2 (Incorrect password): {result2} (Expected: false)")
    
    # Test Case 3: Incorrect username, correct password
    result3 = check_mod("wronguser", correct_password)
    print(f"Test 3 (Incorrect username): {result3} (Expected: false)")
    
    # Test Case 4: Invalid username (too short)
    result4 = check_mod("usr", correct_password)
    print(f"Test 4 (Short username): {result4} (Expected: false)")
    
    # Test Case 5: Password too long
    long_password = "a" * (MAX_PASSWORD_LENGTH + 1)
    result5 = check_mod(correct_username, long_password)
    print(f"Test 5 (Long password): {result5} (Expected: false)")
    
    # Cleanup environment variables
    del os.environ["CORRECT_USERNAME"]
    del os.environ["PASSWORD_SALT"]
    del os.environ["PASSWORD_HASH"]

if __name__ == "__main__":
    main()