import hashlib
import secrets
import os

# In-memory dictionary to simulate a user database
user_database = {}

# Configuration for PBKDF2
ITERATIONS = 210000
KEY_LENGTH = 32  # 32 bytes = 256 bits
SALT_SIZE = 16   # 16 bytes = 128 bits
HASH_ALGORITHM = 'sha256'

def hash_password(password: str) -> str:
    """
    Hashes a password with a randomly generated salt.
    Returns the salt and hash, concatenated and hex-encoded.
    """
    salt = secrets.token_bytes(SALT_SIZE)
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    # Store as "salt:hash" in hex format
    return f"{salt.hex()}:{key.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a password against a stored salt and hash.
    """
    try:
        salt_hex, key_hex = stored_hash.split(':')
        salt = bytes.fromhex(salt_hex)
        key = bytes.fromhex(key_hex)
    except (ValueError, IndexError):
        return False

    new_key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=KEY_LENGTH
    )
    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(key, new_key)

def update_user_password(username: str, new_password: str, database: dict) -> bool:
    """
    Updates a user's password in the simulated database.
    """
    if not username or not username.strip():
        print("Update failed: Username cannot be empty.")
        return False
    if not new_password or len(new_password) < 12:
        print("Update failed: Password must be at least 12 characters long.")
        return False
    
    # In a real application, you might check if the user exists first.
    # if username not in database:
    #     print(f"Update failed: User '{username}' not found.")
    #     return False

    new_hashed_password = hash_password(new_password)
    database[username] = new_hashed_password
    print(f"Password for user '{username}' has been updated successfully.")
    return True

def main():
    """Main function with test cases."""
    print("--- Running Test Cases ---")

    # Test Case 1: Create a new user with a strong password
    print("\n[Test Case 1: Create new user 'alice']")
    update_user_password("alice", "Str0ngP@ssw0rd123!", user_database)
    print(f"Current DB state: {user_database}")
    
    # Test Case 2: Verify the correct password
    print("\n[Test Case 2: Verify correct password for 'alice']")
    is_verified = verify_password("Str0ngP@ssw0rd123!", user_database.get("alice"))
    print(f"Verification result: {'Success' if is_verified else 'Failure'}")

    # Test Case 3: Verify an incorrect password
    print("\n[Test Case 3: Verify incorrect password for 'alice']")
    is_verified = verify_password("WrongPassword!", user_database.get("alice"))
    print(f"Verification result: {'Success' if is_verified else 'Failure'}")
    
    # Test Case 4: Update the password for an existing user
    print("\n[Test Case 4: Update password for 'alice']")
    update_user_password("alice", "EvenM0reSecur3P@ss!", user_database)
    print(f"Current DB state: {user_database}")
    
    # Test Case 5: Verify the new password
    print("\n[Test Case 5: Verify the new password for 'alice']")
    is_verified = verify_password("EvenM0reSecur3P@ss!", user_database.get("alice"))
    print(f"Verification result: {'Success' if is_verified else 'Failure'}")
    
    print("\n--- Additional Tests ---")
    # Test Case 6: Attempt to update password with a weak password
    print("\n[Test Case 6: Attempt weak password for 'bob']")
    update_user_password("bob", "weak", user_database)

    # Test Case 7: Attempt to update password with an empty username
    print("\n[Test Case 7: Attempt update with empty username]")
    update_user_password(" ", "ValidPassword12345", user_database)


if __name__ == "__main__":
    main()