import os
import hashlib

# This dictionary simulates a database. In a real application, you would use a
# proper database system (e.g., PostgreSQL, MySQL).
user_database = {}
SALT_LENGTH = 16 # 16 bytes = 128 bits
# It's recommended to use a high number of iterations for PBKDF2
ITERATIONS = 100000

def register_user(username, password, database):
    """
    Registers a new user by generating a salt, hashing the password,
    and storing the information in the simulated database.

    NOTE: This implementation uses PBKDF2, a key derivation function that is more
    suited for password hashing than a simple SHA-256 hash, as it includes
    iterations to make brute-force attacks slower. Other strong algorithms
    like Argon2, scrypt, or bcrypt are also excellent choices.

    Args:
        username (str): The username.
        password (str): The plain-text password.
        database (dict): The dictionary simulating the database.

    Returns:
        bool: True if registration is successful, False otherwise.
    """
    if not username or not password:
        print("Error: Username and password cannot be empty.")
        return False
    if username in database:
        print(f"Error: Username '{username}' already exists.")
        return False

    # 1. Generate a cryptographically secure salt
    salt = os.urandom(SALT_LENGTH)

    # 2. Hash the password with the salt using PBKDF2-HMAC-SHA256
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )

    # 3. Store username, salt, and hashed password
    # NOTE: In a real database, salt and hashed_password would be stored as
    # BLOB/BINARY types or Base64/Hex encoded strings.
    database[username] = {
        'salt': salt,
        'hashed_password': hashed_password
    }
    print(f"User '{username}' registered successfully.")
    return True

def main():
    """ Main function with 5 test cases """
    print("--- Running Python Test Cases ---")
    
    # Test Case 1: Standard registration
    register_user("alice", "Password123!", user_database)

    # Test Case 2: Another standard registration
    register_user("bob", "MySecureP@ssw0rd", user_database)

    # Test Case 3: Attempt to register a user that already exists
    register_user("alice", "AnotherPassword", user_database)

    # Test Case 4: Registration with a simple password
    register_user("charlie", "password", user_database)

    # Test Case 5: Registration with special characters in username
    register_user("dave-the-admin", "P@$$w0rd_W1th_Ch@r$", user_database)

    # Print the final state of the simulated database
    print("\n--- Final Database State ---")
    for username, data in user_database.items():
        # Printing salt and hash as hex for readability
        print(f"Username: {username}, Salt: {data['salt'].hex()}, Hashed Password: {data['hashed_password'].hex()}")

if __name__ == "__main__":
    main()