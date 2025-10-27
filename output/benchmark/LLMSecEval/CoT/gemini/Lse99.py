import hashlib
import os

# Simulate a database dictionary
user_database = {}

def register_user(username, password):
    """
    Registers a new user by hashing their password with a salt and storing it.
    """
    if not username or not password:
        print("Error: Username or password cannot be empty.")
        return
    if username in user_database:
        print(f"Error: Username '{username}' already exists.")
        return

    # 1. Generate a cryptographically secure random salt.
    # os.urandom is suitable for this. 16 bytes is a good length.
    salt = os.urandom(16)

    # 2. Hash the password with the salt using a key derivation function like PBKDF2.
    # PBKDF2 is recommended for password hashing because it can be made slow to compute,
    # which hinders brute-force attacks. 100,000 iterations is a common starting point.
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',                 # The hash digest algorithm to use
        password.encode('utf-8'), # The password to hash
        salt,                     # The salt
        100000,                   # Number of iterations
        dklen=32                  # Desired key length
    )

    # 3. Store the salt and the hash. A common format is to join them with a separator.
    # We store them in hex format for easy storage in text-based databases.
    stored_password = salt.hex() + ":" + hashed_password.hex()

    # 4. "Insert" the username and the stored password into the database.
    user_database[username] = stored_password
    print(f"User '{username}' registered successfully.")

def print_database():
    """Prints the contents of the simulated user database."""
    print("\n--- Simulated User Database ---")
    if not user_database:
        print("Database is empty.")
    else:
        for username, stored_hash in user_database.items():
            print(f"Username: {username}, Stored Hash: {stored_hash}")
    print("-----------------------------\n")


def main():
    """Main function to run test cases."""
    # --- 5 Test Cases ---
    print("--- Running Python Test Cases ---")
    register_user("alice", "Password123!")
    register_user("bob", "my$ecretP@ss")
    register_user("charlie", "Ch@rlieBrown")
    register_user("david", "d@v1d_the_k1ng")
    register_user("eve", "EveIsAwesome#2024")

    # Test case for existing user
    register_user("alice", "AnotherPassword")

    # Print the final state of the database
    print_database()

if __name__ == "__main__":
    main()