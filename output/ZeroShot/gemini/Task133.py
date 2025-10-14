import os
import hashlib
import time
import secrets
import re

# --- In-memory user store (for simulation) ---
user_database = {}

# --- Security Constants ---
SALT_LENGTH = 16  # 16 bytes for salt
TOKEN_LENGTH_BYTES = 32 # 32 bytes for a secure token
HASH_ALGORITHM = 'sha256'
HASH_ITERATIONS = 600000 # Recommended by OWASP as of 2023 for PBKDF2-HMAC-SHA256
TOKEN_VALIDITY_SECONDS = 15 * 60  # 15 minutes
MIN_PASSWORD_LENGTH = 8
# Password must contain at least one digit, one lowercase, one uppercase, and one special character.
PASSWORD_POLICY = re.compile(r"^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\S+$).{8,}$")


def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes a password with a salt using PBKDF2."""
    pwd_bytes = password.encode('utf-8')
    key = hashlib.pbkdf2_hmac(HASH_ALGORITHM, pwd_bytes, salt, HASH_ITERATIONS)
    return key

def generate_token() -> str:
    """Generates a cryptographically secure URL-safe token."""
    return secrets.token_urlsafe(TOKEN_LENGTH_BYTES)

def request_password_reset(username: str) -> str | None:
    """
    Initiates the password reset process for a user.
    In a real application, the returned token would be sent to the user's email.
    """
    if username not in user_database:
        # To prevent user enumeration, we silently fail. The function's behavior
        # should appear the same whether the user exists or not.
        return None
    
    user = user_database[username]
    token = generate_token()
    user['reset_token'] = token
    user['token_expiry'] = time.time() + TOKEN_VALIDITY_SECONDS
    return token

def reset_password(username: str, token: str, new_password: str) -> bool:
    """Resets the user's password if the provided token is valid."""
    if username not in user_database:
        return False

    user = user_database[username]

    # 1. Validate token
    stored_token = user.get('reset_token')
    if not stored_token or not secrets.compare_digest(stored_token, token):
        return False
        
    # 2. Check token expiration
    if time.time() > user.get('token_expiry', 0):
        user['reset_token'] = None # Expired, invalidate it
        return False
        
    # 3. Invalidate token immediately after first use
    user['reset_token'] = None
    user['token_expiry'] = None

    # 4. Validate new password against policy
    if len(new_password) < MIN_PASSWORD_LENGTH or not PASSWORD_POLICY.match(new_password):
        return False # Password does not meet policy

    # 5. Update password
    new_salt = os.urandom(SALT_LENGTH)
    user['salt'] = new_salt
    user['hashed_password'] = hash_password(new_password, new_salt)
    
    return True

def check_password(username: str, password: str) -> bool:
    """Helper to check password for login simulation."""
    if username not in user_database:
        return False
    user = user_database[username]
    attempt_hash = hash_password(password, user['salt'])
    return secrets.compare_digest(user['hashed_password'], attempt_hash)

def main():
    """Main function with test cases."""
    # --- Setup: Create some users ---
    initial_pass_alice = "AlicePass123!"
    salt_alice = os.urandom(SALT_LENGTH)
    hash_alice = hash_password(initial_pass_alice, salt_alice)
    user_database["alice"] = {
        "username": "alice", "hashed_password": hash_alice, "salt": salt_alice
    }

    initial_pass_bob = "BobSecure@2023"
    salt_bob = os.urandom(SALT_LENGTH)
    hash_bob = hash_password(initial_pass_bob, salt_bob)
    user_database["bob"] = {
        "username": "bob", "hashed_password": hash_bob, "salt": salt_bob
    }
    
    print("--- Running Password Reset Test Cases ---")

    # --- Test Case 1: Successful Reset ---
    print("\n[Test Case 1: Successful Reset]")
    token1 = request_password_reset("alice")
    print(f"Alice requested reset. Token received: {token1 is not None}")
    new_password1 = "NewSecurePass!456"
    success1 = reset_password("alice", token1, new_password1)
    print(f"Password reset attempt with valid token: {'SUCCESS' if success1 else 'FAIL'}")
    print(f"Alice can log in with new password: {check_password('alice', new_password1)}")
    print(f"Alice cannot log in with old password: {not check_password('alice', initial_pass_alice)}")

    # --- Test Case 2: Invalid Token ---
    print("\n[Test Case 2: Invalid Token]")
    token2 = request_password_reset("bob")
    print(f"Bob requested reset. Token received: {token2 is not None}")
    success2 = reset_password("bob", "invalid-token-string", "SomePassword1!")
    print(f"Password reset attempt with invalid token: {'SUCCESS' if success2 else 'FAIL'}")
    print(f"Bob can still log in with old password: {check_password('bob', initial_pass_bob)}")

    # --- Test Case 3: Expired Token ---
    print("\n[Test Case 3: Expired Token]")
    token3 = request_password_reset("bob")
    # Manually expire the token for testing
    user_database["bob"]['token_expiry'] = time.time() - 1
    print("Bob requested reset. Token is now expired.")
    success3 = reset_password("bob", token3, "AnotherPass!789")
    print(f"Password reset attempt with expired token: {'SUCCESS' if success3 else 'FAIL'}")
    print(f"Bob can still log in with old password: {check_password('bob', initial_pass_bob)}")
    
    # --- Test Case 4: Weak Password ---
    print("\n[Test Case 4: Weak Password]")
    token4 = request_password_reset("alice")
    print("Alice requested reset again.")
    success4 = reset_password("alice", token4, "weak")
    print(f"Password reset attempt with weak password: {'SUCCESS' if success4 else 'FAIL'}")
    print(f"Alice can still log in with her last valid password: {check_password('alice', new_password1)}")

    # --- Test Case 5: Non-Existent User ---
    print("\n[Test Case 5: Non-Existent User]")
    token5 = request_password_reset("dave")
    print(f"Request reset for non-existent user 'dave'. Token received: {token5 is not None}")
    success5 = reset_password("dave", "any-token", "anyPassword1!")
    print(f"Password reset attempt for non-existent user: {'SUCCESS' if success5 else 'FAIL'}")

if __name__ == "__main__":
    main()