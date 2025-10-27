import os
import hashlib
import binascii

# In-memory dictionary to simulate a database
user_database = {}

# Constants for hashing
SALT_LENGTH = 16  # 16 bytes = 128 bits
ITERATION_COUNT = 65536
KEY_LENGTH = 32  # 32 bytes = 256 bits for SHA256
HASH_ALGORITHM = 'sha256'

def register_user(username, password):
    """
    Registers a new user by hashing their password and storing it.
    The salt is prepended to the hashed password for storage.
    """
    if not username or not password:
        print("Username and password cannot be empty.")
        return False
    if username in user_database:
        return False  # User already exists

    # Generate a random salt
    salt = os.urandom(SALT_LENGTH)

    # Hash the password with the salt
    hashed_password = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATION_COUNT,
        dklen=KEY_LENGTH
    )
    
    # Store salt and hashed password
    user_database[username] = {
        'salt': salt,
        'hashed_password': hashed_password
    }
    return True

def verify_password(username, password):
    """
    Verifies a user's password during login.
    """
    if username not in user_database:
        return False  # User not found

    stored_credentials = user_database[username]
    salt = stored_credentials['salt']
    stored_hash = stored_credentials['hashed_password']

    # Hash the provided password with the stored salt
    provided_password_hash = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATION_COUNT,
        dklen=KEY_LENGTH
    )

    # Compare the hashes
    return provided_password_hash == stored_hash

# Main function with test cases
if __name__ == "__main__":
    print("--- Python Test Cases ---")

    # Test Case 1: Successful registration
    reg1 = register_user("alice", "Password123!")
    print(f"Test 1 - Alice registration: {'Success' if reg1 else 'Fail'}")

    # Test Case 2: Successful login
    login1 = verify_password("alice", "Password123!")
    print(f"Test 2 - Alice successful login: {'Success' if login1 else 'Fail'}")

    # Test Case 3: Failed login (wrong password)
    login2 = verify_password("alice", "WrongPassword")
    print(f"Test 3 - Alice failed login (wrong password): {'Success' if not login2 else 'Fail'}")

    # Test Case 4: Failed login (non-existent user)
    login3 = verify_password("bob", "Password123!")
    print(f"Test 4 - Bob failed login (user not found): {'Success' if not login3 else 'Fail'}")

    # Test Case 5: Failed registration (duplicate username)
    reg2 = register_user("alice", "AnotherPassword")
    print(f"Test 5 - Alice duplicate registration: {'Success' if not reg2 else 'Fail'}")
    
    # Optional: Print stored data for verification (in hex format)
    if "alice" in user_database:
        creds = user_database["alice"]
        print("\nStored data for Alice:")
        print("Salt: " + binascii.hexlify(creds['salt']).decode('ascii'))
        print("Hashed Password: " + binascii.hexlify(creds['hashed_password']).decode('ascii'))