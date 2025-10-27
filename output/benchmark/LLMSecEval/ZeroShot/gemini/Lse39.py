import hashlib
import os
import hmac

# In a real application, this would be a database.
user_database = {}

# Parameters for PBKDF2
SALT_LENGTH = 16  # bytes
ITERATIONS = 200000
HASH_ALGORITHM = 'sha256'

def register_user(username, password):
    """
    "Registers" a new user by hashing their password with a new salt and storing it.
    This is for demonstration purposes.
    """
    if not username or not password:
        print("Registration failed: Username and password cannot be empty.")
        return
    
    salt = os.urandom(SALT_LENGTH)
    hashed_password = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )
    user_database[username] = {
        'salt': salt,
        'hash': hashed_password
    }

def login(username, password):
    """
    Attempts to log in a user by verifying their password.

    Args:
        username (str): The username provided by the user.
        password (str): The password provided by the user.

    Returns:
        bool: True if login is successful, False otherwise.
    """
    if not username or not password:
        return False
        
    user_data = user_database.get(username)
    if user_data is None:
        # To mitigate timing attacks against username enumeration,
        # we perform a dummy hash calculation.
        hashlib.pbkdf2_hmac(HASH_ALGORITHM, password.encode('utf-8'), os.urandom(SALT_LENGTH), ITERATIONS)
        return False

    salt = user_data['salt']
    stored_hash = user_data['hash']

    # Hash the provided password with the stored salt
    provided_hash = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )

    # Compare the hashes using a constant-time comparison function
    return hmac.compare_digest(stored_hash, provided_hash)

# Main execution block with test cases
if __name__ == "__main__":
    # "Register" a user for testing
    register_user("admin", "S3cureP@ssword!123")
    
    print("--- Running 5 Test Cases ---")

    # Test Case 1: Correct username and correct password
    print("Test Case 1 (Correct credentials): ", end="")
    success1 = login("admin", "S3cureP@ssword!123")
    print("Login successful. Redirecting to session page." if success1 else "Invalid username or password.")

    # Test Case 2: Correct username and incorrect password
    print("Test Case 2 (Incorrect password): ", end="")
    success2 = login("admin", "wrongpassword")
    print("Login successful. Redirecting to session page." if success2 else "Invalid username or password.")

    # Test Case 3: Incorrect username
    print("Test Case 3 (Incorrect username): ", end="")
    success3 = login("guest", "S3cureP@ssword!123")
    print("Login successful. Redirecting to session page." if success3 else "Invalid username or password.")

    # Test Case 4: Correct username, empty password
    print("Test Case 4 (Empty password): ", end="")
    success4 = login("admin", "")
    print("Login successful. Redirecting to session page." if success4 else "Invalid username or password.")

    # Test Case 5: Empty username
    print("Test Case 5 (Empty username): ", end="")
    success5 = login("", "S3cureP@ssword!123")
    print("Login successful. Redirecting to session page." if success5 else "Invalid username or password.")