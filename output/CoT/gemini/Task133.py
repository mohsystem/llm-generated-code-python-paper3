import re
import secrets
import os

# --- User Data Store ---
# In a real application, this would be a database.
user_store = {}

# --- Security Configuration ---
MIN_PASSWORD_LENGTH = 12
# Regex: At least one digit, one lowercase, one uppercase, one special character.
PASSWORD_PATTERN = re.compile(
    r'^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\S+$).{' + str(MIN_PASSWORD_LENGTH) + r',}$'
)

# User model is represented as a dictionary:
# 'username': {
#     'password_hash': '...',
#     'reset_token': '...'
# }

def hash_password(password):
    """
    SECURITY: This is a placeholder for a real password hashing function.
    NEVER store passwords in plaintext or with a simple scheme like this.
    Use a standard library like passlib or argon2-cffi.
    Example: from passlib.context import CryptContext; pwd_context = CryptContext(schemes=["bcrypt"])
             return pwd_context.hash(password)
    """
    return f"hashed_{password}"

def is_password_strong(password):
    """Validates if a new password meets the security policy."""
    return password and PASSWORD_PATTERN.match(password) is not None

def generate_reset_token():
    """Generates a cryptographically secure random token."""
    return secrets.token_hex(32)  # 256 bits of entropy

def request_password_reset(username):
    """
    Initiates a password reset request for a user.
    SECURITY: To prevent user enumeration, this function's observable behavior
    should be the same whether the user exists or not. In a real app, you would
    email the token if the user exists, but always return a generic success message.
    For this example, we return the token for testing.
    """
    token = generate_reset_token()
    if username in user_store:
        user_store[username]['reset_token'] = token
    # Returned for demonstration; in reality, this would be emailed.
    return token

def reset_password(username, token, new_password):
    """
    Resets the user's password if the token is valid and the new password is strong.
    """
    # 1. Validate new password strength
    if not is_password_strong(new_password):
        print(f"Password reset failed for {username}: New password is too weak.")
        return False

    # 2. Validate user and token
    user = user_store.get(username)
    if not user or 'reset_token' not in user or user['reset_token'] != token:
        print(f"Password reset failed for {username}: Invalid username or token.")
        return False

    # 3. Update password and invalidate token
    user['password_hash'] = hash_password(new_password)
    user['reset_token'] = None  # Invalidate token after use

    print(f"Password for {username} has been reset successfully.")
    return True

def main():
    """Main function with test cases."""
    # Pre-populate user store
    user_store["alice"] = {'password_hash': hash_password("Password123!"), 'reset_token': None}
    user_store["bob"] = {'password_hash': hash_password("SecurePass456@"), 'reset_token': None}

    print("--- Running 5 Test Cases ---")

    # Test Case 1: Successful Password Reset
    print("\n--- Test Case 1: Successful Reset ---")
    alice_token = request_password_reset("alice")
    print(f"Alice requested a reset token: {alice_token}")
    success1 = reset_password("alice", alice_token, "NewStrongP@ssw0rd123")
    print(f"Result: {'SUCCESS' if success1 else 'FAILURE'}")

    # Test Case 2: Failed Reset - Invalid Token
    print("\n--- Test Case 2: Invalid Token ---")
    bob_token = request_password_reset("bob")
    print(f"Bob requested a reset token: {bob_token}")
    success2 = reset_password("bob", "thisIsAWrongToken12345", "AnotherP@ssword1")
    print(f"Result: {'SUCCESS' if success2 else 'FAILURE'}")

    # Test Case 3: Failed Reset - Weak Password
    print("\n--- Test Case 3: Weak Password ---")
    # Bob's token is still valid
    success3 = reset_password("bob", bob_token, "weak")
    print(f"Result: {'SUCCESS' if success3 else 'FAILURE'}")

    # Test Case 4: Failed Reset - Non-existent User
    print("\n--- Test Case 4: Non-existent User ---")
    charlie_token = request_password_reset("charlie")
    print(f"A token was generated for a potential user 'charlie': {charlie_token}")
    success4 = reset_password("charlie", charlie_token, "StrongP@ssword123")
    print(f"Result: {'SUCCESS' if success4 else 'FAILURE'}")

    # Test Case 5: Failed Reset - Token Reuse
    print("\n--- Test Case 5: Token Reuse ---")
    # First, a valid reset for bob
    first_reset = reset_password("bob", bob_token, "BobNewP@ssw0rd987")
    print(f"Bob's first reset attempt with valid token: {'SUCCESS' if first_reset else 'FAILURE'}")
    # Now, try to reuse the same token
    print("Attempting to reuse Bob's token...")
    success5 = reset_password("bob", bob_token, "SomeOtherP@ssw0rd")
    print(f"Result: {'SUCCESS' if success5 else 'FAILURE'}")

if __name__ == "__main__":
    main()