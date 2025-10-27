import hashlib
import os

# A simple in-memory dictionary to simulate a database.
# In a real application, this would be a proper database.
user_database = {}

# Constants for hashing
SALT_BYTES = 16
HASH_ALGORITHM = 'sha256'
HASH_ITERATIONS = 260000 # Recommended by OWASP for PBKDF2-SHA256

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes the password using PBKDF2."""
    if not isinstance(password, str) or not isinstance(salt, bytes):
        raise TypeError("Password must be a string and salt must be bytes.")
    
    pwd_hash = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        HASH_ITERATIONS
    )
    return pwd_hash

def register_user(username: str, password: str) -> None:
    """
    "Inserts" a new user into the database after hashing their password.
    Returns the stored data as a dictionary for demonstration.
    """
    if not username or not password:
        print("Error: Username and password cannot be empty.")
        return None

    if username in user_database:
        print(f"Error: Username '{username}' already exists.")
        return None
        
    # Generate a cryptographically secure random salt
    salt = os.urandom(SALT_BYTES)
    
    # Hash the password
    hashed_password = hash_password(password, salt)
    
    # In a real DB, you'd store the salt and hashed password.
    # We store them here in hex format for readability.
    user_data = {
        'salt': salt.hex(),
        'hashed_password': hashed_password.hex()
    }
    
    # Simulate inserting into the database
    user_database[username] = user_data
    print(f"User '{username}' registered successfully.")


def main():
    """Main function with 5 test cases."""
    print("--- Running 5 Test Cases ---")
    
    register_user("alice", "Password123!")
    register_user("bob", "My$trongP@ssw0rd")
    register_user("charlie", "Ch@rlieBrown")
    register_user("diana", "Secr3t-P@ss")
    register_user("eve", "password")

    print("\n--- Simulated Database State ---")
    for username, data in user_database.items():
        print(f"'{username}': {data}")

if __name__ == "__main__":
    main()