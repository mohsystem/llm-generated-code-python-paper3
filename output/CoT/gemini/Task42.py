import os
import hashlib
import hmac

# In-memory storage for user credentials. In a real application, use a database.
_user_store = {}
_SALT_LENGTH = 16  # 16 bytes salt

def _hash_password(password: str, salt: bytes) -> bytes:
    """Hashes the password with a given salt using SHA-256."""
    # It's common to use a key derivation function like PBKDF2 here,
    # but for simplicity, we'll use a salted hash.
    hasher = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Number of iterations
    )
    return hasher

def register_user(username: str, password: str) -> bool:
    """
    Registers a new user.
    :param username: The username.
    :param password: The password.
    :return: True if registration is successful, False if user already exists.
    """
    if username in _user_store:
        return False  # User already exists

    salt = os.urandom(_SALT_LENGTH)
    hashed_password = _hash_password(password, salt)
    _user_store[username] = {'salt': salt, 'hash': hashed_password}
    return True

def login_user(username: str, password: str) -> bool:
    """
    Authenticates a user.
    :param username: The username.
    :param password: The password.
    :return: True if authentication is successful, False otherwise.
    """
    if username not in _user_store:
        return False  # User not found

    stored_credentials = _user_store[username]
    stored_salt = stored_credentials['salt']
    stored_hash = stored_credentials['hash']

    provided_password_hash = _hash_password(password, stored_salt)

    # Use hmac.compare_digest for constant-time comparison to prevent timing attacks
    return hmac.compare_digest(stored_hash, provided_password_hash)

def main():
    """Main function with test cases."""
    print("--- Python User Authentication System Test ---")

    # Test Case 1: Successful registration
    print("Test 1: Registering a new user 'alice'.")
    reg_success = register_user("alice", "Password123!")
    print(f"Registration successful: {reg_success}")
    print()

    # Test Case 2: Successful login
    print("Test 2: 'alice' attempts to log in with correct password.")
    login_success = login_user("alice", "Password123!")
    print(f"Login successful: {login_success}")
    print()

    # Test Case 3: Failed login (wrong password)
    print("Test 3: 'alice' attempts to log in with incorrect password.")
    login_fail_wrong_pass = login_user("alice", "WrongPassword!")
    print(f"Login successful: {login_fail_wrong_pass}")
    print()

    # Test Case 4: Failed login (non-existent user)
    print("Test 4: Non-existent user 'bob' attempts to log in.")
    login_fail_no_user = login_user("bob", "SomePassword")
    print(f"Login successful: {login_fail_no_user}")
    print()

    # Test Case 5: Failed registration (duplicate username)
    print("Test 5: Attempting to register 'alice' again.")
    reg_fail_duplicate = register_user("alice", "AnotherPassword")
    print(f"Registration successful: {reg_fail_duplicate}")
    print()

if __name__ == "__main__":
    main()