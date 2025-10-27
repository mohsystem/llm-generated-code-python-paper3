import hashlib
import os

# In-memory dictionary to simulate a database. 
# In a real application, use a proper database (e.g., PostgreSQL, MySQL).
user_database = {}

def hash_password(password, salt):
    """
    Hashes the password using PBKDF2 with HMAC SHA-256.
    PBKDF2 is a secure choice for password hashing as it includes salting and 
    key stretching (iterations) to protect against brute-force attacks.
    """
    # hashlib recommends at least 100,000 iterations for SHA-256.
    # OWASP recommends 600,000 for PBKDF2-HMAC-SHA256. We'll use a high number.
    iterations = 390000 
    key_length = 32  # 32 bytes = 256 bits
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=key_length)
    return hashed_password

def generate_salt():
    """Generates a cryptographically strong salt."""
    return os.urandom(16)  # 16 bytes is a good size for a salt.

def register_user(database, username, password, first_name, last_name, email):
    """
    Registers a new user by hashing their password and storing the details.
    """
    if not username or not password:
        return "Username and password cannot be empty."

    if username in database:
        return "Username already exists."

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    database[username] = {
        'hashed_password': hashed_password,
        'salt': salt,
        'first_name': first_name,
        'last_name': last_name,
        'email': email
    }
    return "Registration succeeded."

def main():
    """Main function with 5 test cases."""
    print("--- Running 5 Test Cases for User Registration ---")
    
    # Test Case 1: Successful registration
    result1 = register_user(user_database, "jdoe", "Password123!", "John", "Doe", "j.doe@example.com")
    print(f"Test 1 (New User): {result1}")
    if 'jdoe' in user_database:
        print(f"   > User 'jdoe' found in DB. Hash: {user_database['jdoe']['hashed_password'].hex()[:16]}...")

    # Test Case 2: Attempting to register with an existing username
    result2 = register_user(user_database, "jdoe", "AnotherPass", "Jane", "Doe", "jane.d@example.com")
    print(f"Test 2 (Existing User): {result2}")

    # Test Case 3: Successful registration of a different user
    result3 = register_user(user_database, "asmith", "SecureP@ssw0rd", "Alice", "Smith", "a.smith@example.com")
    print(f"Test 3 (Another New User): {result3}")
    if 'asmith' in user_database:
        print(f"   > User 'asmith' found in DB. Hash: {user_database['asmith']['hashed_password'].hex()[:16]}...")
        
    # Test Case 4: Registration with an empty password
    result4 = register_user(user_database, "bwhite", "", "Bob", "White", "b.white@example.com")
    print(f"Test 4 (Empty Password): {result4}")

    # Test Case 5: Registration with an empty username
    result5 = register_user(user_database, "", "Pass123", "Charlie", "Chaplin", "c.c@example.com")
    print(f"Test 5 (Empty Username): {result5}")

    print("\n--- Final Database State ---")
    print(f"Total users registered: {len(user_database)}")
    for username in user_database:
        print(f"- {username}")

if __name__ == "__main__":
    main()