import hashlib
import hmac

# In-memory storage for username -> hashedPassword.
# In a real application, this would be a database.
# Passwords should be hashed before storing.
# "password123" -> "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
# "adminPass!" -> "1b87a86c6d2038314e3843b0927e85489839473b13411c5240212f458133503f"
USER_DATABASE = {
    "user1": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
    "admin": "1b87a86c6d2038314e3843b0927e85489839473b13411c5240212f458133503f"
}

def hash_password(password: str) -> str:
    """Hashes a password using SHA-256."""
    if not password:
        return ""
    # In a real app, use a salt and a key derivation function like bcrypt or Argon2
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def authenticate_user(users: dict, username: str, password: str) -> bool:
    """
    Authenticates a user against the stored credentials.
    :param users: A dictionary of username -> hashed_password.
    :param username: The username to authenticate.
    :param password: The password to check.
    :return: True if authentication is successful, False otherwise.
    """
    # 1. Basic input validation
    if not username or not password:
        return False

    # 2. Check if user exists
    stored_hash = users.get(username)
    if not stored_hash:
        return False

    # 3. Hash the provided password
    input_hash = hash_password(password)

    # 4. Securely compare the hashes (constant-time comparison)
    return hmac.compare_digest(stored_hash, input_hash)

def main():
    """Main function with test cases."""
    print("--- Python Test Cases ---")

    # Test Case 1: Correct username, correct password
    result1 = authenticate_user(USER_DATABASE, "user1", "password123")
    print(f"Test 1 (user1, password123): {'Success' if result1 else 'Failure'}")

    # Test Case 2: Correct username, incorrect password
    result2 = authenticate_user(USER_DATABASE, "user1", "wrongpassword")
    print(f"Test 2 (user1, wrongpassword): {'Success' if result2 else 'Failure'}")

    # Test Case 3: Incorrect username
    result3 = authenticate_user(USER_DATABASE, "unknownuser", "password123")
    print(f"Test 3 (unknownuser, password123): {'Success' if result3 else 'Failure'}")

    # Test Case 4: Correct username, empty password
    result4 = authenticate_user(USER_DATABASE, "admin", "")
    print(f"Test 4 (admin, ''): {'Success' if result4 else 'Failure'}")

    # Test Case 5: Empty username
    result5 = authenticate_user(USER_DATABASE, "", "somepass")
    print(f"Test 5 ('', somepass): {'Success' if result5 else 'Failure'}")

if __name__ == "__main__":
    main()