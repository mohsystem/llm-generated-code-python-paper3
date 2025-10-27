import hashlib
import os
import binascii

# In a real application, this would be a secure database.
user_database = {}

def register_user(username, password):
    """
    Registers a new user by hashing their password with a salt.
    :param username: The username.
    :param password: The password.
    :return: A dictionary with username, salt (hex), and hashed_password (hex), or None on failure.
    """
    if not username or not password:
        print("Registration failed: Username and password cannot be empty.")
        return None

    # In a real app, check if the username already exists.
    if username in user_database:
        print(f"Registration failed: Username '{username}' already exists.")
        return None

    # Generate a cryptographically secure random salt.
    # os.urandom is suitable for cryptographic use.
    salt = os.urandom(16)  # 16 bytes = 128 bits

    # Use PBKDF2 for password hashing, which is recommended for this purpose.
    # Use a high number of iterations to slow down brute-force attacks.
    iterations = 100000
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',          # The hash digest algorithm
        password.encode('utf-8'),  # Convert the password to bytes
        salt,              # Provide the salt
        iterations,        # Number of iterations
        dklen=32           # Desired key length in bytes
    )

    # Convert salt and hash to hex for storage/display
    salt_hex = binascii.hexlify(salt).decode('utf-8')
    hashed_password_hex = binascii.hexlify(hashed_password).decode('utf-8')
    
    # Store the user record (simulated)
    user_database[username] = {'salt': salt_hex, 'hashed_password': hashed_password_hex}
    
    print(f"User '{username}' registered successfully.")
    print(f"  - Salt (Hex): {salt_hex}")
    print(f"  - Hashed Password (Hex): {hashed_password_hex}")
    print("------------------------------------")
    
    return {
        'username': username,
        'salt': salt_hex,
        'hashed_password': hashed_password_hex
    }


def main():
    """Main function with test cases."""
    print("--- Python Registration Test Cases ---")
    register_user("alice", "Password123!")
    register_user("bob", "my$ecretP@ss")
    register_user("charlie", "aVeryLongAndComplexPassword")
    register_user("dave", "short")
    register_user("alice", "new_password") # Test existing user
    print(f"Total users in DB: {len(user_database)}")


if __name__ == "__main__":
    main()