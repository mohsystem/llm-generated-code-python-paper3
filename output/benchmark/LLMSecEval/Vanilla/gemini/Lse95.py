import os
import hashlib
import hmac

# In-memory dictionary to simulate a database
database = {}
SALT_LENGTH = 16

def generate_salt():
    """Generates a cryptographically secure random salt."""
    return os.urandom(SALT_LENGTH)

def hash_password(password, salt):
    """Hashes a password with a salt using SHA-256."""
    password_bytes = password.encode('utf-8')
    # Append salt to password before hashing
    combined = password_bytes + salt
    return hashlib.sha256(combined).digest()

def register_user(username, password):
    """Registers a new user by storing their username, salt, and hashed password."""
    if username in database:
        print(f"Registration failed: Username '{username}' already exists.")
        return False
    salt = generate_salt()
    hashed_pwd = hash_password(password, salt)
    database[username] = {'salt': salt, 'hashed_password': hashed_pwd}
    print(f"Registration successful for username: {username}")
    return True

def verify_login(username, password):
    """Verifies a user's login credentials."""
    user_data = database.get(username)
    if not user_data:
        print(f"Login failed: Username '{username}' not found.")
        return False
    
    salt = user_data['salt']
    stored_hashed_pwd = user_data['hashed_password']
    
    # Hash the entered password with the stored salt
    entered_hashed_pwd = hash_password(password, salt)
    
    # Use hmac.compare_digest to prevent timing attacks
    if hmac.compare_digest(stored_hashed_pwd, entered_hashed_pwd):
        print(f"Login successful for username: {username}")
        return True
    else:
        print(f"Login failed: Incorrect password for username '{username}'.")
        return False

def main():
    """Main function with test cases."""
    print("--- Test Case 1: Successful Registration ---")
    register_user("alice", "password123")
    
    print("\n--- Test Case 2: Successful Login ---")
    verify_login("alice", "password123")
    
    print("\n--- Test Case 3: Failed Login (Incorrect Password) ---")
    verify_login("alice", "wrongpassword")
    
    print("\n--- Test Case 4: Failed Login (User Not Found) ---")
    verify_login("bob", "password123")
    
    print("\n--- Test Case 5: Failed Registration (Username Exists) ---")
    register_user("alice", "anotherpassword")

if __name__ == "__main__":
    main()