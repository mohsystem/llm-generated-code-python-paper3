import hashlib
import os
import secrets
import re
import time
from typing import Dict, Optional, Tuple

# Security constants
SALT_LENGTH = 16
TOKEN_LENGTH_BYTES = 32
PBKDF2_ITERATIONS = 310000
HASH_ALGORITHM = 'sha256'
TOKEN_VALIDITY_SECONDS = 300  # 5 minutes

# In-memory storage for demonstration. Use a secure database in production.
user_database: Dict[str, Dict] = {}
token_store: Dict[str, Dict] = {}


def _hash(data: str, salt: bytes) -> bytes:
    """Hashes data using PBKDF2-HMAC-SHA256."""
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        data.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32  # 256 bits
    )
    return key


def is_password_strong(password: str) -> bool:
    """Checks if a password meets the complexity requirements."""
    if not password or len(password) < 12:
        return False
    # Requires at least one digit, one lowercase, one uppercase, one special character
    pattern = re.compile(r"^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#&()–[{}]:;',?/*~$^+=<>]).{12,}$")
    return bool(pattern.match(password))


def create_user(username: str, password: str) -> bool:
    """Creates a new user with a securely hashed password."""
    if not username or username in user_database:
        return False
    if not is_password_strong(password):
        return False
    
    salt = secrets.token_bytes(SALT_LENGTH)
    hashed_password = _hash(password, salt)
    user_database[username] = {'salt': salt, 'hash': hashed_password}
    return True


def request_password_reset(username: str) -> Optional[str]:
    """Generates and stores a password reset token for a user."""
    if not username or username not in user_database:
        return None  # User not found

    plain_text_token = secrets.token_urlsafe(TOKEN_LENGTH_BYTES)
    
    token_salt = secrets.token_bytes(SALT_LENGTH)
    hashed_token = _hash(plain_text_token, token_salt)
    expiration = time.time() + TOKEN_VALIDITY_SECONDS

    token_store[username] = {
        'salt': token_salt,
        'hash': hashed_token,
        'expiration': expiration
    }
    
    return plain_text_token


def reset_password(username: str, token: str, new_password: str) -> bool:
    """Resets the user's password if the token is valid."""
    if not all([username, token, new_password]) or username not in user_database:
        return False

    stored_token_info = token_store.get(username)
    if not stored_token_info:
        return False  # No pending reset request

    if time.time() > stored_token_info['expiration']:
        del token_store[username]  # Clean up expired token
        return False  # Token expired

    provided_token_hash = _hash(token, stored_token_info['salt'])

    # Use constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(provided_token_hash, stored_token_info['hash']):
        return False  # Invalid token

    if not is_password_strong(new_password):
        return False  # New password does not meet policy

    # All checks passed, update password and invalidate token
    new_salt = secrets.token_bytes(SALT_LENGTH)
    new_hashed_password = _hash(new_password, new_salt)
    user_database[username]['salt'] = new_salt
    user_database[username]['hash'] = new_hashed_password
    
    del token_store[username]  # Invalidate token after use

    return True


def main():
    """Main function with test cases."""
    print("Running password reset tests...")
    username = "testuser"
    initial_password = "Password!12345"
    new_password = "NewPassword@54321"

    # Setup: Create a user
    if create_user(username, initial_password):
        print(f"1. User '{username}' created successfully.")
    else:
        print("1. Failed to create user.")
        return

    # Test Case 1: Successful password reset
    print("\n--- Test Case 1: Successful Reset ---")
    token1 = request_password_reset(username)
    print(f"Generated reset token: {token1}")
    success1 = reset_password(username, token1, new_password)
    print(f"Reset result: {'SUCCESS' if success1 else 'FAILURE'}")
    assert success1, "Expected SUCCESS"

    # Test Case 2: Attempt to reuse the token
    print("\n--- Test Case 2: Reuse Token (Should Fail) ---")
    success2 = reset_password(username, token1, "AnotherPassword$99")
    print(f"Reset result: {'SUCCESS' if success2 else 'FAILURE'}")
    assert not success2, "Expected FAILURE"

    # Test Case 3: Attempt to reset with a wrong token
    print("\n--- Test Case 3: Wrong Token (Should Fail) ---")
    token3 = request_password_reset(username)
    print(f"Generated new reset token: {token3}")
    success3 = reset_password(username, "wrongTokenAbc123", new_password)
    print(f"Reset result: {'SUCCESS' if success3 else 'FAILURE'}")
    assert not success3, "Expected FAILURE"

    # Test Case 4: Attempt to reset with a weak password
    print("\n--- Test Case 4: Weak New Password (Should Fail) ---")
    token4 = request_password_reset(username)  # Request a valid token
    success4 = reset_password(username, token4, "weak")
    print(f"Reset result for weak password: {'SUCCESS' if success4 else 'FAILURE'}")
    assert not success4, "Expected FAILURE"

    # Test Case 5: Expired token
    print("\n--- Test Case 5: Expired Token (Should Fail) ---")
    global TOKEN_VALIDITY_SECONDS
    original_expiry = TOKEN_VALIDITY_SECONDS
    TOKEN_VALIDITY_SECONDS = 1  # Set a short expiry for the test
    token5 = request_password_reset(username)
    print("Waiting for token to expire...")
    time.sleep(2)
    success5 = reset_password(username, token5, new_password)
    print(f"Reset result for expired token: {'SUCCESS' if success5 else 'FAILURE'}")
    assert not success5, "Expected FAILURE"
    TOKEN_VALIDITY_SECONDS = original_expiry  # Reset expiry time

if __name__ == "__main__":
    main()