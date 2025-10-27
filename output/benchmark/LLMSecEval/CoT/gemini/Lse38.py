import hashlib
import os
import hmac

# In-memory dictionary to simulate a user database.
# In a real application, this would be a database.
_USER_DATABASE = {}

def _hash_password(password, salt):
    """Hashes a password with a given salt using SHA-256."""
    # It's recommended to use a key derivation function like PBKDF2 or Argon2
    # for password hashing, but for this simple example, we use salted SHA-256.
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Number of iterations
    )
    return pwd_hash

def register_user(username, password):
    """Simulates user registration by adding a user to the 'database'."""
    if not username or not password:
        print(f"Registration failed for '{username}': Username and password cannot be empty.")
        return
        
    salt = os.urandom(16)  # Generate a cryptographically secure salt
    hashed_password = _hash_password(password, salt)
    _USER_DATABASE[username] = {'salt': salt, 'hash': hashed_password}

def login(username, password):
    """
    Simulates a login attempt.
    :param username: The username provided by the user.
    :param password: The password provided by the user.
    :return: A string indicating the result of the login attempt.
    """
    if not username or not password:
        return "Invalid credentials. Redirecting to login page."

    user_data = _USER_DATABASE.get(username)
    if user_data is None:
        # User not found. To prevent username enumeration, we can perform a dummy hash
        # and comparison, but for this example, a generic message is sufficient.
        return "Invalid credentials. Redirecting to login page."
    
    salt = user_data['salt']
    stored_hash = user_data['hash']
    
    # Hash the provided password with the stored salt
    provided_hash = _hash_password(password, salt)
    
    # Use a constant-time comparison to prevent timing attacks
    if hmac.compare_digest(stored_hash, provided_hash):
        return "Login successful. Redirecting to dashboard."
    else:
        return "Invalid credentials. Redirecting to login page."

def main():
    """Main function to run test cases."""
    # Setup: Register users for testing
    register_user("admin", "Password123!")
    register_user("user", "userpass")

    print("--- Running 5 Test Cases ---")

    # Test Case 1: Correct username and password
    print("Test 1: Correct credentials ('admin', 'Password123!')")
    print(f"Result: {login('admin', 'Password123!')}\n")
    
    # Test Case 2: Correct username, incorrect password
    print("Test 2: Correct username, incorrect password ('admin', 'wrongpass')")
    print(f"Result: {login('admin', 'wrongpass')}\n")

    # Test Case 3: Incorrect username
    print("Test 3: Incorrect username ('guest', 'Password123!')")
    print(f"Result: {login('guest', 'Password123!')}\n")

    # Test Case 4: Correct username, empty password
    print("Test 4: Correct username, empty password ('user', '')")
    print(f"Result: {login('user', '')}\n")

    # Test Case 5: Empty username
    print("Test 5: Empty username ('', 'userpass')")
    print(f"Result: {login('', 'userpass')}\n")

if __name__ == "__main__":
    main()