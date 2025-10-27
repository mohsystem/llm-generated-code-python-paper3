import hashlib
import os

def register_user(username, password):
    """
    Hashes a password with a salt and simulates inserting the user record.
    Uses PBKDF2-HMAC-SHA256, a recommended algorithm for password hashing.

    :param username: The username to register.
    :param password: The plaintext password.
    :return: A tuple of (username, salt_hex, hashed_password_hex).
    """
    print(f"Registering user: {username}")
    
    # 1. Generate a cryptographically secure random salt
    salt = os.urandom(16)  # 16 bytes is a good salt length

    # 2. Hash the password with the salt using PBKDF2
    # 100,000 iterations is a common baseline
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm
        password.encode('utf-8'),  # Convert the password to bytes
        salt,  # Provide the salt
        100000  # It is recommended to use at least 100,000 iterations
    )

    # Convert binary salt and hash to hex for storage
    salt_hex = salt.hex()
    hashed_password_hex = hashed_password.hex()

    # 3. Simulate inserting into the database
    print("  -> Simulating database insert...")
    print(f"     Username: {username}")
    print(f"     Salt: {salt_hex}")
    print(f"     Hashed Password: {hashed_password_hex}")
    print("Registration complete.\n")

    return username, salt_hex, hashed_password_hex

if __name__ == "__main__":
    # 5 Test Cases
    register_user("alice", "Password123!")
    register_user("bob", "my$ecretP@ss")
    register_user("charlie", "qwerty")
    register_user("diana", "12345678")
    register_user("eve", "pa$$w0rd")