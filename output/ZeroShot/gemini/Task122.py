import os
import hashlib
import hmac

# scrypt parameters - use values recommended by OWASP
# N=2^14, r=8, p=1 is a good starting point
N = 16384
R = 8
P = 1
SALT_SIZE = 16
HASH_SIZE = 32

def signup(password: str) -> str:
    """
    Stores a user password securely by generating a salt and hashing the password using scrypt.
    :param password: The plaintext password to store.
    :return: A string containing the salt and hash, separated by a colon, in hex format.
    """
    salt = os.urandom(SALT_SIZE)
    # The password must be encoded to bytes before hashing
    password_bytes = password.encode('utf-8')
    
    # Use scrypt for password hashing
    hashed_password = hashlib.scrypt(
        password_bytes, salt=salt, n=N, r=R, p=P, dklen=HASH_SIZE
    )
    
    # Return salt and hash as hex strings for easy storage
    return f"{salt.hex()}:{hashed_password.hex()}"

def verify_password(password: str, stored_password: str) -> bool:
    """
    Verifies a plaintext password against a stored salted hash.
    :param password: The plaintext password to verify.
    :param stored_password: The stored string containing the salt and hash.
    :return: True if the password is correct, False otherwise.
    """
    try:
        salt_hex, stored_hash_hex = stored_password.split(':')
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(stored_hash_hex)
        
        password_bytes = password.encode('utf-8')
        
        # Hash the provided password with the same salt and parameters
        test_hash = hashlib.scrypt(
            password_bytes, salt=salt, n=N, r=R, p=P, dklen=HASH_SIZE
        )
        
        # Use hmac.compare_digest for constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_hash, test_hash)
    except (ValueError, TypeError):
        # Catches errors from splitting or hex decoding, indicating invalid format
        return False

def main():
    """Main function with test cases."""
    print("--- Python Password Hashing Tests ---")

    # Test Case 1: Sign up a user and store the password hash
    print("\n[Test Case 1: Signup with 'password123']")
    user1_password = "password123"
    stored_user1 = signup(user1_password)
    print(f"Stored format for '{user1_password}': {stored_user1}")

    # Test Case 2: Verify with the correct password
    print("\n[Test Case 2: Verify with correct password 'password123']")
    is_correct = verify_password(user1_password, stored_user1)
    print(f"Verification successful: {is_correct}")
    if not is_correct:
        print("TEST FAILED!")

    # Test Case 3: Verify with an incorrect password
    print("\n[Test Case 3: Verify with incorrect password 'wrongpassword']")
    is_incorrect = verify_password("wrongpassword", stored_user1)
    print(f"Verification successful: {is_incorrect}")
    if is_incorrect:
        print("TEST FAILED!")

    # Test Case 4: Sign up another user with a different password
    print("\n[Test Case 4: Signup with a different password 'anotherPassword']")
    user2_password = "anotherPassword"
    stored_user2 = signup(user2_password)
    print(f"Stored format for '{user2_password}': {stored_user2}")
    print(f"Hashes for different passwords are different: {stored_user1 != stored_user2}")

    # Test Case 5: Sign up with the same password again, salt should be different
    print("\n[Test Case 5: Signup with 'password123' again]")
    stored_user1_again = signup(user1_password)
    print(f"Second stored format for '{user1_password}': {stored_user1_again}")
    print(f"Hashes for the same password are different due to salt: {stored_user1 != stored_user1_again}")

if __name__ == "__main__":
    main()