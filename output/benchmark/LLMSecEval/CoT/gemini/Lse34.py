import hashlib
import hmac

# Simulates a database table of users.
# In a real application, this would be a database, and passwords
# would be hashed with a strong, salted algorithm like BCrypt or Argon2.
# Passwords are pre-hashed for demonstration.
# Hashed with SHA-256: "password123", "adminPass", "securePwd!"
USER_DATABASE = {
    "alice": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
    "bob": "e2a8c80f688f52d9a5189755b72194a34599a0720239645b8364e015ad61b409",
    "charlie": "84d284752c03565f1295b92049d5b42d708846c8e31a0e6c5597793e5e4925e0"
}

def hash_password(password: str) -> str:
    """
    Hashes a password using SHA-256.
    NOTE: In a real-world scenario, use a stronger, salted hashing algorithm
    like bcrypt or Argon2.
    """
    if not isinstance(password, str):
        return ""
    password_bytes = password.encode('utf-8')
    sha256 = hashlib.sha256()
    sha256.update(password_bytes)
    return sha256.hexdigest()

def login(username: str, password: str) -> str:
    """
    Attempts to log a user in.
    :param username: The username entered by the user.
    :param password: The password entered by the user.
    :return: A string indicating the result.
    """
    # 1. Basic input validation
    if not isinstance(username, str) or not username or not isinstance(password, str):
        return "Invalid username or password. Redirecting to login page..."

    # 2. Retrieve the stored hash for the user
    stored_hashed_password = USER_DATABASE.get(username)

    # 3. If user does not exist, return a generic error message
    # to prevent username enumeration attacks.
    if stored_hashed_password is None:
        # We still hash the provided password to make the timing similar
        # to a failed password attempt, which can help mitigate timing attacks.
        hash_password("dummy_password_for_timing")
        return "Invalid username or password. Redirecting to login page..."

    # 4. Hash the provided password
    provided_hashed_password = hash_password(password)

    # 5. Compare the hashes in a way that is resistant to timing attacks.
    passwords_match = hmac.compare_digest(
        stored_hashed_password,
        provided_hashed_password
    )

    if passwords_match:
        return "Login successful! Redirecting to dashboard page..."
    else:
        return "Invalid username or password. Redirecting to login page..."

if __name__ == "__main__":
    print("--- 5 Test Cases ---")

    # Test Case 1: Correct username and password
    print("1. Testing with correct credentials (alice):")
    print(f"   Result: {login('alice', 'password123')}\n")

    # Test Case 2: Correct username, incorrect password
    print("2. Testing with incorrect password (alice):")
    print(f"   Result: {login('alice', 'wrongpassword')}\n")

    # Test Case 3: Incorrect username
    print("3. Testing with non-existent user (david):")
    print(f"   Result: {login('david', 'somepassword')}\n")

    # Test Case 4: Empty input for password
    print("4. Testing with empty password (bob):")
    print(f"   Result: {login('bob', '')}\n")

    # Test Case 5: Correct credentials for another user
    print("5. Testing with correct credentials (charlie):")
    print(f"   Result: {login('charlie', 'securePwd!')}\n")