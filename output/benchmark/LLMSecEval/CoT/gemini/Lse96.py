import hashlib
import os

SALT_LENGTH_BYTES = 16

def generate_salt():
    """Generates a cryptographically secure random salt."""
    return os.urandom(SALT_LENGTH_BYTES)

def hash_password(password, salt):
    """Hashes the password with the given salt using SHA-256."""
    # We use pbkdf2_hmac which is a key derivation function recommended for passwords.
    # It adds iterations (stretching) to make brute-forcing harder.
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Number of iterations
    )
    return pwd_hash

def register_user(username, password):
    """
    Simulates user registration by generating a salt, hashing the password,
    and creating a string for database storage.
    """
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    
    salt_hex = salt.hex()
    hashed_password_hex = hashed_password.hex()
    
    # In a real DB, you might store salt and hash in separate columns.
    # Here, we concatenate them for a single-string representation.
    return salt_hex + hashed_password_hex

def main():
    """Main function with 5 test cases."""
    test_users = [
        ("alice", "Password123!"),
        ("bob", "my$ecr3tP@ssw0rd"),
        ("charlie", "correct-horse-battery-staple"),
        ("david", "12345"),
        ("eve", "eve_password")
    ]

    print("--- Python User Registration Simulation ---")
    for username, password in test_users:
        stored_credential = register_user(username, password)
        print(f"Registering user: {username}")
        print(f"Stored credential: {stored_credential}")
        print()

if __name__ == "__main__":
    main()