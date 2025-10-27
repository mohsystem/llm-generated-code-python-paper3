import hashlib
import os
import secrets
import re

# In a real application, use a proper database. This is for demonstration.
user_database = {}

# Simple email regex for validation
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.salt = secrets.token_bytes(16)
        self.password_hash = self._hash_password(password, self.salt)
        self.is_logged_in = False

    def _hash_password(self, password, salt):
        """Hashes a password using PBKDF2 with HMAC-SHA256."""
        if not password or not isinstance(password, str):
            raise ValueError("Password must be a non-empty string.")
        
        # Rule #7, #8: Use a strong KDF like PBKDF2
        # Use a high iteration count
        kdf = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            260000,
            dklen=32
        )
        return kdf

    def verify_password(self, password):
        """Verifies a password against the stored hash."""
        if not password:
            return False
        
        # Re-hash the provided password with the stored salt
        new_hash = self._hash_password(password, self.salt)
        
        # Rule #7: Use constant-time comparison for secrets
        return secrets.compare_digest(self.password_hash, new_hash)

def change_email(username, old_email, new_email, password):
    """
    Changes the user's email after performing security checks.
    Returns True on success, False on failure.
    """
    # Rule #1: Input Validation
    if not all([username, old_email, new_email, password]):
        print("Error: All fields are required.")
        return False

    if not isinstance(old_email, str) or not isinstance(new_email, str) or not isinstance(password, str):
        print("Error: Invalid input types.")
        return False
        
    if not EMAIL_REGEX.match(new_email):
        print("Error: New email format is invalid.")
        return False

    user = user_database.get(username)

    # Security checks
    if not user:
        # Generic error to prevent user enumeration
        print("Error: Email change failed.")
        return False

    if not user.is_logged_in:
        print("Error: User must be logged in to change email.")
        return False
        
    if new_email == old_email:
        print("Error: New email must be different from the old email.")
        return False
        
    # Constant time comparison is good practice even for non-critical data
    if not secrets.compare_digest(user.email, old_email):
        print("Error: Email change failed.") # Generic error
        return False

    if not user.verify_password(password):
        print("Error: Email change failed.") # Generic error
        return False

    # All checks passed, update the email
    user.email = new_email
    print(f"Email for user '{username}' has been successfully updated to {new_email}")
    return True

def main():
    """Main function with test cases."""
    # Setup: Create a user and log them in
    test_username = "testUser"
    initial_email = "initial@example.com"
    user_password = "Password123!"

    test_user = User(test_username, initial_email, user_password)
    user_database[test_username] = test_user
    
    print(f"Initial state: User '{test_user.username}' with email '{test_user.email}' is logged out.")
    print("--------------------------------------------------")
    
    # --- Test Cases ---
    print("Running Test Cases...\n")

    # Test Case 1: Successful email change
    print("--- Test Case 1: Successful Change ---")
    test_user.is_logged_in = True  # Simulate login
    print("User is now logged in.")
    result1 = change_email(test_username, initial_email, "new.email@example.com", user_password)
    print(f"Result: {'SUCCESS' if result1 else 'FAILURE'}")
    print(f"Current email: {test_user.email}\n")
    updated_email = test_user.email # Save for next tests

    # Test Case 2: Failure - User not logged in
    print("--- Test Case 2: Failure (Not Logged In) ---")
    test_user.is_logged_in = False  # Simulate logout
    print("User is now logged out.")
    result2 = change_email(test_username, updated_email, "another.email@example.com", user_password)
    print(f"Result: {'SUCCESS' if result2 else 'FAILURE'}")
    print(f"Current email: {test_user.email}\n")
    test_user.is_logged_in = True  # Log back in for subsequent tests

    # Test Case 3: Failure - Incorrect password
    print("--- Test Case 3: Failure (Incorrect Password) ---")
    result3 = change_email(test_username, updated_email, "another.email@example.com", "WrongPassword!")
    print(f"Result: {'SUCCESS' if result3 else 'FAILURE'}")
    print(f"Current email: {test_user.email}\n")

    # Test Case 4: Failure - Incorrect old email
    print("--- Test Case 4: Failure (Incorrect Old Email) ---")
    result4 = change_email(test_username, "wrong.old.email@example.com", "another.email@example.com", user_password)
    print(f"Result: {'SUCCESS' if result4 else 'FAILURE'}")
    print(f"Current email: {test_user.email}\n")

    # Test Case 5: Failure - New email is same as old
    print("--- Test Case 5: Failure (New Email is Same as Old) ---")
    result5 = change_email(test_username, updated_email, updated_email, user_password)
    print(f"Result: {'SUCCESS' if result5 else 'FAILURE'}")
    print(f"Current email: {test_user.email}\n")

if __name__ == "__main__":
    main()