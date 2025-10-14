import os
import hashlib
import hmac

class UserAuthSystem:
    SALT_SIZE_BYTES = 16
    HASH_ALGORITHM = 'sha256'
    ITERATIONS = 210000
    KEY_LENGTH_BYTES = 32

    def __init__(self):
        self._user_store = {}

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        """Hashes a password using PBKDF2."""
        return hashlib.pbkdf2_hmac(
            self.HASH_ALGORITHM,
            password.encode('utf-8'),
            salt,
            self.ITERATIONS,
            dklen=self.KEY_LENGTH_BYTES
        )

    def register(self, username: str, password: str) -> bool:
        """
        Registers a new user.
        Returns True on success, False if the user already exists or input is invalid.
        """
        if not username or not password:
            print("Error: Username and password cannot be empty.")
            return False
        if username in self._user_store:
            print(f"Error: User '{username}' already exists.")
            return False

        salt = os.urandom(self.SALT_SIZE_BYTES)
        hashed_password = self._hash_password(password, salt)
        self._user_store[username] = {
            'salt': salt,
            'hashed_password': hashed_password
        }
        return True

    def login(self, username: str, password: str) -> bool:
        """
        Authenticates a user.
        Returns True on success, False otherwise.
        """
        if not username or not password or username not in self._user_store:
            return False

        stored_credentials = self._user_store[username]
        salt = stored_credentials['salt']
        stored_hash = stored_credentials['hashed_password']

        computed_hash = self._hash_password(password, salt)

        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_hash, computed_hash)

if __name__ == '__main__':
    auth = UserAuthSystem()

    # Test Case 1: Register a new user
    print("Test 1: Register 'alice'")
    registered = auth.register("alice", "Password123!")
    print(f"Registration successful: {registered}")
    print("--------------------")

    # Test Case 2: Successful login
    print("Test 2: Successful login for 'alice'")
    login_success = auth.login("alice", "Password123!")
    print(f"Login successful: {login_success}")
    print("--------------------")

    # Test Case 3: Failed login with wrong password
    print("Test 3: Failed login for 'alice' (wrong password)")
    login_fail_password = auth.login("alice", "WrongPassword")
    print(f"Login successful: {login_fail_password}")
    print("--------------------")

    # Test Case 4: Failed login with non-existent user
    print("Test 4: Failed login for non-existent user 'bob'")
    login_fail_user = auth.login("bob", "SomePassword")
    print(f"Login successful: {login_fail_user}")
    print("--------------------")
    
    # Test Case 5: Register a second user and login successfully
    print("Test 5: Register 'bob' and log in")
    registered_bob = auth.register("bob", "anotherSecureP@ssw0rd")
    print(f"Registration of 'bob' successful: {registered_bob}")
    login_bob_success = auth.login("bob", "anotherSecureP@ssw0rd")
    print(f"Login for 'bob' successful: {login_bob_success}")
    print("--------------------")