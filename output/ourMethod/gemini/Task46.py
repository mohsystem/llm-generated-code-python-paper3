import re
import secrets
import hashlib
from typing import Dict, Optional, Tuple

class User:
    def __init__(self, name: str, email: str, password_hash: str, salt: str):
        self.name = name
        self.email = email
        self.password_hash = password_hash
        self.salt = salt

class UserRegistrationSystem:
    _SALT_LENGTH_BYTES = 16
    _PBKDF2_ITERATIONS = 210000
    _PBKDF2_ALGORITHM = 'sha256'

    def __init__(self):
        # In-memory storage for user data, using email as the unique key.
        self._user_database: Dict[str, User] = {}

    def _is_valid_name(self, name: str) -> bool:
        return name is not None and 2 <= len(name.strip()) <= 50

    def _is_valid_email(self, email: str) -> bool:
        if not email:
            return False
        # A reasonably strict regex for email validation
        email_regex = r'^[a-zA-Z0-9_!#$%&\'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$'
        return re.match(email_regex, email) is not None

    def _is_valid_password(self, password: str) -> bool:
        if not password or len(password) < 12:
            return False
        # Requires at least one digit, one lowercase, one uppercase, one special character.
        password_regex = r'^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])(?=\S+$).{12,}$'
        return re.match(password_regex, password) is not None

    def _hash_password(self, password: str) -> Tuple[str, str]:
        """Hashes a password with a securely generated salt using PBKDF2-HMAC-SHA256."""
        salt = secrets.token_bytes(self._SALT_LENGTH_BYTES)
        key = hashlib.pbkdf2_hmac(
            self._PBKDF2_ALGORITHM,
            password.encode('utf-8'),
            salt,
            self._PBKDF2_ITERATIONS
        )
        # Store hash and salt as hex strings
        return key.hex(), salt.hex()

    def register_user(self, name: str, email: str, password: str) -> bool:
        if not self._is_valid_name(name):
            print("Registration failed: Invalid name.", flush=True)
            return False
        if not self._is_valid_email(email):
            print("Registration failed: Invalid email format.", flush=True)
            return False
        if not self._is_valid_password(password):
            print("Registration failed: Password does not meet policy requirements (min 12 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char).", flush=True)
            return False

        if email in self._user_database:
            print("Registration failed: Email already exists.", flush=True)
            return False

        try:
            password_hash, salt = self._hash_password(password)
            new_user = User(name, email, password_hash, salt)
            self._user_database[email] = new_user
            print(f"User '{name}' registered successfully.", flush=True)
            return True
        except Exception as e:
            print(f"An unexpected error occurred during registration: {e}", flush=True)
            return False
            
    def is_user_registered(self, email: str) -> bool:
        return email in self._user_database

def main():
    system = UserRegistrationSystem()
    
    print("--- Test Case 1: Successful Registration ---")
    system.register_user("Alice Smith", "alice.smith@example.com", "Password@12345")
    
    print("\n--- Test Case 2: Duplicate Email ---")
    system.register_user("Alice Jones", "alice.smith@example.com", "AnotherP@ss123")
    
    print("\n--- Test Case 3: Weak Password (no special char) ---")
    system.register_user("Bob Johnson", "bob.j@example.com", "WeakPassword123")
    
    print("\n--- Test Case 4: Invalid Email ---")
    system.register_user("Carol White", "carol.white.com", "StrongPass!123")
    
    print("\n--- Test Case 5: Successful Registration 2 ---")
    system.register_user("David Green", "david.green@example.com", "SecurePassword#2024")

    # Verify database state
    print("\n--- Verifying Database State ---")
    print(f"Is alice.smith@example.com registered? {system.is_user_registered('alice.smith@example.com')}")
    print(f"Is david.green@example.com registered? {system.is_user_registered('david.green@example.com')}")
    print(f"Is bob.j@example.com registered? {system.is_user_registered('bob.j@example.com')}")


if __name__ == "__main__":
    main()