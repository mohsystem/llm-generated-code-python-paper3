import hashlib

# In-memory dictionary to simulate a database
database = {}

def hash_password(password: str) -> str:
    """
    Hashes a password using the SHA-256 algorithm.
    :param password: The plain-text password.
    :return: The SHA-256 hashed password as a hex string.
    """
    # Encode the password to bytes, required by hashlib
    password_bytes = password.encode('utf-8')
    # Create a sha256 hash object
    sha256 = hashlib.sha256()
    # Update the hash object with the password bytes
    sha256.update(password_bytes)
    # Return the hexadecimal representation of the hash
    return sha256.hexdigest()

def register_user(username: str, password: str):
    """
    "Inserts" a new user into the database after hashing their password.
    :param username: The username.
    :param password: The plain-text password.
    """
    if not username or not password:
        print("Registration failed: Username and password cannot be empty.")
        return

    if username in database:
        print(f"Registration failed: Username '{username}' already exists.")
        return
    
    hashed_password = hash_password(password)
    database[username] = hashed_password
    print(f"User '{username}' registered successfully.")

def print_database():
    """Prints the contents of the simulated database."""
    print("\n--- Database Contents ---")
    if not database:
        print("Database is empty.")
    else:
        for username, hashed_pwd in database.items():
            print(f"Username: {username}, Hashed Password: {hashed_pwd}")
    print("-------------------------")

if __name__ == "__main__":
    # 5 Test Cases
    print("--- Running Test Cases ---")
    register_user("alice", "password123")
    register_user("bob", "my$ecret#")
    register_user("charlie", "CharlieBrown")
    register_user("admin", "admin_pass")
    register_user("alice", "new_password")  # Test existing user
    print("--------------------------\n")

    # Print the final state of the database
    print_database()