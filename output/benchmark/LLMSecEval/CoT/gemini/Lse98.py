import hashlib
import os

class UserRegistry:
    """
    A class to simulate a user registration system.
    In a real application, this would interact with a database.
    """
    def __init__(self):
        # This dictionary simulates a user database table.
        # Key: username
        # Value: A dictionary containing 'salt' and 'hashed_password'
        self.user_database = {}

    def hash_password(self, password, salt):
        """Hashes the password with a given salt using SHA-256."""
        # Note: In a real-world application, use a stronger, slower hashing algorithm
        # like Argon2 or bcrypt, available through libraries like 'argon2-cffi' or 'bcrypt'.
        password_bytes = password.encode('utf-8')
        salted_password = salt + password_bytes
        hasher = hashlib.sha256()
        hasher.update(salted_password)
        return hasher.hexdigest()

    def register_user(self, username, password):
        """
        Registers a new user by hashing their password and storing it.
        Returns True on success, False on failure.
        """
        # Basic validation
        if not username or not password:
            print("Registration failed: Username and password cannot be empty.")
            return False
        
        if username in self.user_database:
            print(f"Registration failed: Username '{username}' already exists.")
            return False

        # Generate a cryptographically secure random salt
        salt = os.urandom(16)

        # Hash the password with the salt
        hashed_password = self.hash_password(password, salt)

        # Store the username, salt, and hashed password.
        # In a real app, this would be an INSERT statement using parameterized queries
        # to prevent SQL injection.
        self.user_database[username] = {
            'salt': salt,
            'hashed_password': hashed_password
        }
        
        print(f"User '{username}' registered successfully.")
        return True

    def verify_password(self, username, password):
        """
        Verifies a user's password.
        Returns True if the password is correct, False otherwise.
        """
        if username not in self.user_database:
            return False
        
        user_data = self.user_database[username]
        stored_salt = user_data['salt']
        stored_hash = user_data['hashed_password']

        # Hash the provided password with the user's stored salt
        provided_hash = self.hash_password(password, stored_salt)
        
        # Compare the hashes
        return provided_hash == stored_hash

def main():
    """Main function with test cases."""
    print("--- Running Python Registration Test Cases ---")
    registry = UserRegistry()

    # Test Case 1: Successful registration
    registry.register_user("alice", "password123")

    # Test Case 2: Successful registration
    registry.register_user("bob", "secure_Pa$$w0rd")

    # Test Case 3: Attempt to register a duplicate username
    registry.register_user("alice", "another_password")

    # Test Case 4: Attempt to register with an empty username
    registry.register_user("", "some_password")

    # Test Case 5: Another successful registration
    registry.register_user("david", "d@v1d_r0ck$")

    print("\n--- Verifying Users ---")
    print(f"Login for 'alice' with correct password: {'Success' if registry.verify_password('alice', 'password123') else 'Failed'}")
    print(f"Login for 'alice' with incorrect password: {'Success' if registry.verify_password('alice', 'wrongpassword') else 'Failed'}")
    print(f"Login for 'bob' with correct password: {'Success' if registry.verify_password('bob', 'secure_Pa$$w0rd') else 'Failed'}")
    print(f"Login for non-existent user 'eve': {'Success' if registry.verify_password('eve', 'any_password') else 'Failed'}")
    
    print("\n--- Simulated Database Content ---")
    for username, data in registry.user_database.items():
        print(f"Username: {username}")
        # Use .hex() to display byte string as hex
        print(f"  Salt: {data['salt'].hex()}")
        print(f"  Hashed Password: {data['hashed_password']}")

if __name__ == "__main__":
    main()