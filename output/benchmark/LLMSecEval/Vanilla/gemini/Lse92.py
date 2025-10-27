import hashlib

def register_user(username, password):
    """
    Takes a username and password, and returns the SHA-256 hash of the password.
    
    :param username: The username (not used in hashing).
    :param password: The password to be hashed.
    :return: The hexadecimal string of the hashed password.
    """
    # Create a new sha256 hash object
    sha256 = hashlib.sha256()
    
    # Update the hash object with the password, which must be encoded to bytes
    sha256.update(password.encode('utf-8'))
    
    # Return the hexadecimal digest of the hash
    return sha256.hexdigest()

if __name__ == "__main__":
    # 5 Test Cases
    test_cases = [
        ("admin", "password123"),
        ("user", "P@ssw0rd!"),
        ("guest", ""),
        ("test_user_long_name", "a_very_long_and_secure_password_with_numbers_12345_and_symbols_!@#$"),
        ("another_user", "password123")
    ]
    
    print("--- Python Test Cases ---")
    for username, password in test_cases:
        hashed_password = register_user(username, password)
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"Hashed Password (SHA-256): {hashed_password}")
        print("---------------------------------")