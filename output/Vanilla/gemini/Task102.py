import hashlib

# Simulates a database table of users. Maps username -> hashedPassword
database = {}

def hash_password(password):
    """
    Hashes a password using SHA-256.
    In a real application, you should use a stronger, salted hashing algorithm like bcrypt or Argon2.
    
    :param password: The plain text password.
    :return: The SHA-256 hashed password as a hex string.
    """
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()

def update_user_password(username, new_password, db):
    """
    Updates the user's password in the simulated database.
    
    :param username: The username of the user to update.
    :param new_password: The new plain text password.
    :param db: The database dictionary to update.
    :return: None
    """
    hashed_password = hash_password(new_password)
    db[username] = hashed_password
    print(f"Password for user '{username}' has been updated.")

def main():
    # Initialize database with some users
    database['alice'] = hash_password('initialPass1')
    database['bob'] = hash_password('initialPass2')

    print("--- Initial Database State ---")
    for user, pass_hash in database.items():
        print(f"User: {user}, Hashed Pass: {pass_hash}")
    
    print("\n--- Running 5 Test Cases ---")
    
    # Test Case 1: Update existing user 'alice'
    update_user_password("alice", "newSecurePassword123", database)

    # Test Case 2: Update existing user 'bob'
    update_user_password("bob", "anotherPassword!@#", database)

    # Test Case 3: Add a new user 'charlie'
    update_user_password("charlie", "charliePass2024", database)
    
    # Test Case 4: Update user 'alice' again
    update_user_password("alice", "evenNewerPassword$", database)

    # Test Case 5: Add a new user 'david'
    update_user_password("david", "d@v1d$P@$$", database)
    
    print("\n--- Final Database State ---")
    for user, pass_hash in database.items():
        print(f"User: {user}, Hashed Pass: {pass_hash}")

if __name__ == "__main__":
    main()