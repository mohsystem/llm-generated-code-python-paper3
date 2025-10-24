import os
import secrets
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Dict, Optional, Any
import threading

# Use the cryptography library for a standard, secure KDF implementation
# as recommended by security best practices (Rule #9).
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

# --- Constants for Security Parameters ---

# Salt size: 16 bytes (128 bits) is a standard recommendation.
SALT_BYTES = 16

# Iteration count for PBKDF2: OWASP recommends 600,000 for PBKDF2-HMAC-SHA256
# as of 2023. This is a strong, computationally expensive value to resist brute-force attacks.
# This meets and exceeds the minimum suggested by Rule #8.
PBKDF2_ITERATIONS = 600_000

# Session token size: 32 bytes (256 bits) of entropy provides strong protection
# against guessing.
TOKEN_BYTES = 32

# Session duration in minutes.
SESSION_DURATION_MINUTES = 30


class UserSessionManager:
    """
    Manages user registration, login, and session validation in a thread-safe manner.

    This class handles user credentials securely by hashing and salting passwords
    and provides a session management system with expiring tokens.
    """

    def __init__(self):
        """Initializes the in-memory user and session stores and a lock for thread safety."""
        # In a real application, this data would be stored in a secure database.
        self._users: Dict[str, Dict[str, bytes]] = {}
        self._sessions: Dict[str, Dict[str, Any]] = {}
        # A lock to prevent race conditions when accessing shared user/session data (Rule #11).
        self._lock = threading.Lock()

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        """
        Hashes a password with a given salt using PBKDF2-HMAC-SHA256.

        Args:
            password: The plaintext password to hash.
            salt: A cryptographically secure random salt.

        Returns:
            The derived key (hashed password).
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Output length of 32 bytes (256 bits)
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))

    def _verify_password(self, stored_hash: bytes, salt: bytes, provided_password: str) -> bool:
        """
        Verifies a provided password against a stored hash and salt.

        Args:
            stored_hash: The hash stored for the user.
            salt: The salt stored for the user.
            provided_password: The plaintext password from the user login attempt.

        Returns:
            True if the password is correct, False otherwise.
        """
        if not stored_hash or not salt or not provided_password:
            return False
        
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            # verify() is preferred as it performs a constant-time comparison (Rule #14)
            kdf.verify(provided_password.encode('utf-8'), stored_hash)
            return True
        except InvalidKey:
            # This exception is raised if the verification fails.
            return False

    def register_user(self, username: str, password: str) -> bool:
        """
        Registers a new user if the username is not already taken.

        Args:
            username: The desired username (must be a non-empty string).
            password: The desired password (must be a non-empty string).

        Returns:
            True if registration is successful, False if the user already exists or inputs are invalid.
        """
        if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
            print("Error: Username and password must be non-empty strings.")
            return False

        with self._lock:
            if username in self._users:
                return False  # User already exists

            # Generate a unique, cryptographically secure salt for each user (Rule #4, #5).
            salt = secrets.token_bytes(SALT_BYTES)
            
            hashed_password = self._hash_password(password, salt)

            self._users[username] = {
                'salt': salt,
                'hashed_password': hashed_password
            }
        return True

    def login(self, username: str, password: str) -> Optional[str]:
        """
        Authenticates a user and creates a session upon successful login.

        Args:
            username: The user's username.
            password: The user's password.

        Returns:
            A secure session token on successful login, None otherwise.
        """
        if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
            return None

        with self._lock:
            user_data = self._users.get(username)
            if not user_data:
                # To prevent username enumeration, a generic failure can be returned.
                # For this example, we proceed but will fail at password verification.
                # A secure implementation might add a random delay here.
                return None

            stored_hash = user_data.get('hashed_password', b'')
            salt = user_data.get('salt', b'')

            if self._verify_password(stored_hash, salt, password):
                # Password is correct, create a new session token.
                # secrets.token_hex is used for generating cryptographically strong tokens.
                session_token = secrets.token_hex(TOKEN_BYTES)
                expires_at = datetime.now(timezone.utc) + timedelta(minutes=SESSION_DURATION_MINUTES)
                
                self._sessions[session_token] = {
                    'username': username,
                    'expires_at': expires_at
                }
                return session_token
        
        return None

    def _get_valid_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """
        A private helper to find and validate a session, cleaning up expired ones.
        This centralized logic prevents race conditions between checking and using a session.
        """
        if not isinstance(session_token, str) or not session_token:
            return None

        with self._lock:
            session_data = self._sessions.get(session_token)
            if not session_data:
                return None

            # Check for expiration. All datetimes are timezone-aware (UTC).
            if datetime.now(timezone.utc) > session_data['expires_at']:
                # Clean up expired session to prevent memory leaks.
                del self._sessions[session_token]
                return None
            
            return session_data

    def is_session_valid(self, session_token: str) -> bool:
        """
        Checks if a session token is valid and not expired.

        Args:
            session_token: The session token to validate.

        Returns:
            True if the session is valid, False otherwise.
        """
        return self._get_valid_session(session_token) is not None

    def get_username_from_session(self, session_token: str) -> Optional[str]:
        """
        Retrieves the username associated with a valid session token.

        Args:
            session_token: The session token.

        Returns:
            The username if the session is valid, None otherwise.
        """
        session_data = self._get_valid_session(session_token)
        if session_data:
            return session_data.get('username')
        return None

    def logout(self, session_token: str) -> bool:
        """
        Logs a user out by invalidating their session token.

        Args:
            session_token: The session token to invalidate.

        Returns:
            True if the session was found and invalidated, False otherwise.
        """
        if not isinstance(session_token, str) or not session_token:
            return False

        with self._lock:
            if session_token in self._sessions:
                del self._sessions[session_token]
                return True
        return False

def main():
    """Main function with 5 test cases to demonstrate functionality."""
    manager = UserSessionManager()

    print("--- Test Case 1: Register a new user ---")
    username = "testuser1"
    password = "VeryStrongPassword!@#$1234"
    success = manager.register_user(username, password)
    print(f"Registration for '{username}': {'Success' if success else 'Failed'}")
    assert success, "Test Case 1 Failed: Should register successfully"

    print("\n--- Test Case 2: Attempt to register the same user again ---")
    success_again = manager.register_user(username, password)
    print(f"Second registration for '{username}': {'Success' if success_again else 'Failed'}")
    assert not success_again, "Test Case 2 Failed: Should not allow duplicate registration"

    print("\n--- Test Case 3: Log in with correct credentials ---")
    session_token = manager.login(username, password)
    print(f"Login for '{username}' with correct password: {'Success (token received)' if session_token else 'Failed'}")
    assert session_token is not None, "Test Case 3 Failed: Should receive a session token"
    
    print("\n--- Test Case 4: Log in with incorrect credentials ---")
    wrong_password = "WrongPassword!456"
    failed_token = manager.login(username, wrong_password)
    print(f"Login for '{username}' with incorrect password: {'Success' if failed_token else 'Failed (no token)'}")
    assert failed_token is None, "Test Case 4 Failed: Should not receive a token for wrong password"

    print("\n--- Test Case 5: Session validation and logout ---")
    is_valid = manager.is_session_valid(session_token)
    print(f"Is session token valid before logout? {is_valid}")
    assert is_valid, "Test Case 5a Failed: Session should be valid"

    user = manager.get_username_from_session(session_token)
    print(f"Username from valid session: {user}")
    assert user == username, "Test Case 5b Failed: Should get correct username"

    logout_success = manager.logout(session_token)
    print(f"Logout successful? {logout_success}")
    assert logout_success, "Test Case 5c Failed: Logout should be successful"

    is_valid_after_logout = manager.is_session_valid(session_token)
    print(f"Is session token valid after logout? {is_valid_after_logout}")
    assert not is_valid_after_logout, "Test Case 5d Failed: Session should be invalid after logout"

    print("\n--- Extra Test Case: Login attempt for a non-existent user ---")
    non_existent_user = "ghost"
    non_existent_token = manager.login(non_existent_user, "anypassword")
    print(f"Login for non-existent user '{non_existent_user}': {'Success' if non_existent_token else 'Failed (no token)'}")
    assert non_existent_token is None, "Extra Test Case Failed: Should not log in non-existent user"

    print("\nAll test cases passed!")


if __name__ == "__main__":
    main()