import hashlib
import hmac
import os

# A simple in-memory dictionary to act as a user database.
# In a real application, this would be a proper database (e.g., SQL, NoSQL).
user_database = {}

def register_user(username, password):
    """
    "Registers" a new user by securely hashing their password and storing it.
    In a real app, this would save to a database.
    """
    if not username or not password:
        print("Registration failed: Username and password cannot be empty.")
        return
    if username in user_database:
        print(f"Registration failed: Username '{username}' already exists.")
        return

    # Generate a cryptographically secure random salt.
    salt = os.urandom(16)
    
    # Hash the password using PBKDF2 with HMAC-SHA256. This is a strong,
    # industry-standard algorithm for password storage.
    # The iteration count should be high to make brute-forcing difficult.
    iterations = 260000 
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )
    
    user_database[username] = {
        'salt': salt,
        'hash': hashed_password
    }
    print(f"User '{username}' registered successfully.")

def login_user(username, password):
    """
    Attempts to log a user in by securely verifying their credentials.
    Returns a string indicating the result of the login attempt.
    """
    # Check if user exists. Use a generic message for failures to prevent username enumeration.
    if not username or not password or username not in user_database:
        return "Login failed: Invalid username or password. Redirecting to login page."

    user_credentials = user_database.get(username)
    salt = user_credentials['salt']
    stored_hash = user_credentials['hash']
    
    # Hash the provided password with the user's stored salt using the same parameters.
    iterations = 260000
    provided_password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )
    
    # Use hmac.compare_digest for a constant-time comparison to prevent timing attacks.
    if hmac.compare_digest(stored_hash, provided_password_hash):
        return "Login successful! Redirecting to dashboard..."
    else:
        return "Login failed: Invalid username or password. Redirecting to login page."

if __name__ == "__main__":
    # Setup: Register a user for testing
    test_user = "testUser"
    test_pass = "P@ssword123!"
    register_user(test_user, test_pass)
    print("\n--- Running Test Cases ---")

    # Test Case 1: Successful Login
    print("Test Case 1: Correct username and password.")
    result1 = login_user(test_user, test_pass)
    print(f"Result: {result1}")
    print("--------------------------")

    # Test Case 2: Incorrect Password
    print("Test Case 2: Correct username, incorrect password.")
    result2 = login_user(test_user, "WrongPassword")
    print(f"Result: {result2}")
    print("--------------------------")

    # Test Case 3: Incorrect Username
    print("Test Case 3: Incorrect username.")
    result3 = login_user("nonexistentUser", test_pass)
    print(f"Result: {result3}")
    print("--------------------------")

    # Test Case 4: Case-sensitive Username
    print("Test Case 4: Case-sensitive username check (should fail).")
    result4 = login_user("testuser", test_pass)
    print(f"Result: {result4}")
    print("--------------------------")

    # Test Case 5: Empty Password
    print("Test Case 5: Correct username, empty password (should fail).")
    result5 = login_user(test_user, "")
    print(f"Result: {result5}")
    print("--------------------------")