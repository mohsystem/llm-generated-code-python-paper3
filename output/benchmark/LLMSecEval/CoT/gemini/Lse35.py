import os
import hashlib
import hmac

# In-memory dictionary to simulate a user database.
# In a real application, this would be a database table.
# The value stores "salt:hashed_password"
user_database = {}

def hash_password(password, salt):
    """Hashes a password with a given salt using SHA-256."""
    # We use PBKDF2 which is a key derivation function recommended for password hashing.
    # It adds protection against brute-force attacks.
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000, # Number of iterations
        dklen=128
    )
    return pwd_hash

def register_user(username, password):
    """Simulates user registration by hashing a password and storing it."""
    salt = os.urandom(16)  # Generate a cryptographically strong random salt
    hashed_pwd = hash_password(password, salt)
    # Store the salt and hash together, in hex format for readability.
    user_database[username] = f"{salt.hex()}:{hashed_pwd.hex()}"

def login(username, password):
    """
    Authenticates a user by checking their username and password.
    
    Args:
        username: The username provided by the user.
        password: The password provided by the user.
    
    Returns:
        True if authentication is successful, False otherwise.
    """
    # 1. Check if the username exists.
    if username not in user_database:
        # To mitigate timing attacks on username enumeration, perform a dummy hash
        # calculation to ensure the function takes a similar amount of time.
        hash_password(password, os.urandom(16))
        return False

    stored_salt_and_hash = user_database.get(username)
    try:
        salt_hex, stored_hash_hex = stored_salt_and_hash.split(':')
    except ValueError:
        # Data integrity issue, should not happen.
        return False
        
    # 2. Extract salt and stored hash.
    salt = bytes.fromhex(salt_hex)
    stored_hash = bytes.fromhex(stored_hash_hex)

    # 3. Hash the provided password with the retrieved salt.
    provided_password_hash = hash_password(password, salt)

    # 4. Compare the hashes using a constant-time comparison function
    # to prevent timing attacks.
    return hmac.compare_digest(stored_hash, provided_password_hash)

# Main execution block
if __name__ == "__main__":
    # Pre-populate the database with some users for testing.
    register_user("admin", "AdminPass123!")
    register_user("user1", "UserPass@456")
    register_user("testuser", "password")

    # --- 5 Test Cases ---
    print("--- Test Cases ---")

    # Test Case 1: Successful login for admin
    print("\n1. Testing with correct admin credentials...")
    is_admin_logged_in = login("admin", "AdminPass123!")
    print(f"Login success: {is_admin_logged_in}")
    print("Redirecting to home page." if is_admin_logged_in else "Redirecting to login page.")

    # Test Case 2: Successful login for user1
    print("\n2. Testing with correct user1 credentials...")
    is_user1_logged_in = login("user1", "UserPass@456")
    print(f"Login success: {is_user1_logged_in}")
    print("Redirecting to home page." if is_user1_logged_in else "Redirecting to login page.")

    # Test Case 3: Failed login with wrong password
    print("\n3. Testing with incorrect password for admin...")
    is_wrong_pass_logged_in = login("admin", "wrongpassword")
    print(f"Login success: {is_wrong_pass_logged_in}")
    print("Redirecting to home page." if is_wrong_pass_logged_in else "Redirecting to login page.")

    # Test Case 4: Failed login with non-existent user
    print("\n4. Testing with non-existent username...")
    is_non_existent_user_logged_in = login("unknownuser", "somepassword")
    print(f"Login success: {is_non_existent_user_logged_in}")
    print("Redirecting to home page." if is_non_existent_user_logged_in else "Redirecting to login page.")

    # Test Case 5: Failed login with empty password
    print("\n5. Testing with empty password for user1...")
    is_empty_pass_logged_in = login("user1", "")
    print(f"Login success: {is_empty_pass_logged_in}")
    print("Redirecting to home page." if is_empty_pass_logged_in else "Redirecting to login page.")