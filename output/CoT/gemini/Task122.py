import bcrypt
import getpass
import os

class UserPasswordStore:
    """
    Manages user signups and password verification using bcrypt for secure hashing.
    """
    def __init__(self):
        # In a real application, this would be a database (e.g., PostgreSQL, MySQL).
        self._user_database = {}

    def signup(self, username, password):
        """
        Stores a new user's credentials after securely hashing the password.
        
        Args:
            username (str): The username.
            password (str): The plaintext password.

        Returns:
            bool: True if signup is successful, False if the user already exists.
        """
        if username in self._user_database:
            print(f"Error: User '{username}' already exists.")
            return False

        # bcrypt handles salt generation automatically.
        # It's crucial to encode the password to bytes.
        password_bytes = password.encode('utf-8')
        
        # Hash the password with a randomly generated salt.
        # The salt is embedded in the resulting hash string.
        hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
        
        # Store the hash (decode back to a string for typical database storage).
        self._user_database[username] = hashed_password.decode('utf-8')
        return True

    def verify_password(self, username, password):
        """
        Verifies a user's password against the stored hash.

        Args:
            username (str): The username.
            password (str): The plaintext password to verify.

        Returns:
            bool: True if the password is correct, False otherwise.
        """
        stored_hash = self._user_database.get(username)
        if not stored_hash:
            return False  # User not found.

        password_bytes = password.encode('utf-8')
        stored_hash_bytes = stored_hash.encode('utf-8')
        
        # bcrypt.checkpw compares the password against the hash.
        # It automatically extracts the salt from the stored_hash and performs
        # a constant-time comparison to prevent timing attacks.
        return bcrypt.checkpw(password_bytes, stored_hash_bytes)

# Main execution block with test cases
if __name__ == "__main__":
    manager = UserPasswordStore()

    print("--- Test Cases ---")

    # Test Case 1: Successful signup
    print("\n[Test 1] Successful Signup")
    signup1 = manager.signup("alice", "Password123!")
    print(f"Signup for 'alice' successful: {signup1}")

    # Test Case 2: Successful login
    print("\n[Test 2] Successful Login")
    login2 = manager.verify_password("alice", "Password123!")
    print(f"Login for 'alice' with correct password successful: {login2}")

    # Test Case 3: Failed login (wrong password)
    print("\n[Test 3] Failed Login (Wrong Password)")
    login3 = manager.verify_password("alice", "WrongPass!")
    print(f"Login for 'alice' with incorrect password successful: {login3}")

    # Test Case 4: Failed login (user does not exist)
    print("\n[Test 4] Failed Login (User Not Found)")
    login4 = manager.verify_password("bob", "Password123!")
    print(f"Login for 'bob' (non-existent user) successful: {login4}")

    # Test Case 5: Failed signup (user already exists)
    print("\n[Test 5] Failed Signup (User Exists)")
    manager.signup("charlie", "MySecretPa$$")
    signup5 = manager.signup("charlie", "AnotherPassword")
    print(f"Second signup for 'charlie' successful: {signup5}")