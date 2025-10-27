import os
import hashlib

# In-memory user database (for demonstration purposes)
# Format: { 'username': {'salt': b'...', 'hash': b'...'} }
user_database = {}
SALT_LENGTH = 16

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes a password with a given salt using SHA-256."""
    # It is recommended to use a key derivation function like PBKDF2, bcrypt, or scrypt
    # hashlib.pbkdf2_hmac is a good choice from the standard library.
    # For this example, we use a simple salted hash.
    pwd_bytes = password.encode('utf-8')
    return hashlib.sha256(salt + pwd_bytes).digest()

def register_user(username: str, password: str) -> bool:
    """
    Registers a new user by generating a salt, hashing the password,
    and storing the details.
    """
    if username in user_database:
        print(f"Registration failed: Username '{username}' already exists.")
        return False
    
    # Generate a cryptographically secure random salt
    salt = os.urandom(SALT_LENGTH)
    
    # Hash the password with the salt
    hashed_password = hash_password(password, salt)
    
    # Store the salt and hashed password
    user_database[username] = {'salt': salt, 'hash': hashed_password}
    print(f"User '{username}' registered successfully.")
    return True

def login_user(username: str, password: str) -> bool:
    """
    Verifies a user's login credentials.
    """
    if username not in user_database:
        print(f"Login failed: User '{username}' not found.")
        return False
    
    user_data = user_database[username]
    salt = user_data['salt']
    stored_hash = user_data['hash']
    
    # Hash the provided password with the stored salt
    provided_hash = hash_password(password, salt)
    
    # Compare the hashes
    if provided_hash == stored_hash:
        print(f"Login successful for user '{username}'.")
        return True
    else:
        print(f"Login failed: Incorrect password for user '{username}'.")
        return False

def Lse95():
    """Main function to run test cases."""
    print("--- Running Test Cases ---")

    # Test Case 1: Register a new user
    print("\n[Test Case 1: Successful Registration]")
    register_user("alice", "Password123!")

    # Test Case 2: Successful Login
    print("\n[Test Case 2: Successful Login]")
    login_user("alice", "Password123!")

    # Test Case 3: Failed Login (Wrong Password)
    print("\n[Test Case 3: Failed Login - Wrong Password]")
    login_user("alice", "WrongPassword")

    # Test Case 4: Failed Registration (Username already exists)
    print("\n[Test Case 4: Failed Registration - User Exists]")
    register_user("alice", "AnotherPassword")

    # Test Case 5: Failed Login (User does not exist)
    print("\n[Test Case 5: Failed Login - User Not Found]")
    login_user("bob", "Password123!")

    print("\n--- Test Cases Finished ---")

if __name__ == "__main__":
    Lse95()