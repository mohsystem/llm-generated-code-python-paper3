import hashlib
import os

def hash_password(password):
    """
    Hashes a password with a randomly generated salt using PBKDF2.

    Args:
        password (str): The password to hash.

    Returns:
        str: A string containing the salt and hash, separated by a colon.
    """
    # Generate a random salt
    # os.urandom provides cryptographically secure random bytes
    salt = os.urandom(16)
    
    # Hash the password using PBKDF2
    # 100,000 iterations is a good starting point in 2023.
    # The number should be increased over time as computing power grows.
    key = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100,000 iterations
    )
    
    # Store the salt and hash, commonly encoded to hex for readability
    # The salt must be stored alongside the hash to verify the password later
    return salt.hex() + ':' + key.hex()

def register_user(username, password):
    """
    Simulates a user registration by hashing the password.
    """
    print(f"Registering user: {username}")
    hashed_password = hash_password(password)
    print(f"Stored information for {username}:")
    print(f"  Username: {username}")
    print(f"  Hashed Password (salt:hash): {hashed_password}")
    print("------------------------------------")

if __name__ == "__main__":
    # 5 Test Cases
    register_user("alice", "Password123!")
    register_user("bob", "My$trongP@ssw0rd")
    register_user("charlie", "Secr3t#Key")
    register_user("david", "123456")
    register_user("eve", "password")