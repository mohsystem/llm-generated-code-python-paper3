import os
import hashlib
import secrets

# In-memory user database simulation. In a real application, this would be a database.
# Key: username, Value: a string containing salt and hashed password
user_database = {}

# Constants for PBKDF2
SALT_BYTES = 16
ITERATIONS = 310000  # OWASP recommendation for PBKDF2-HMAC-SHA256
HASH_ALGORITHM = 'sha256'

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes a password with a given salt using PBKDF2."""
    key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS
    )
    return key

def register_user(username: str, password: str):
    """
    Simulates user registration by hashing the password and storing it.
    """
    # Rule #1: Input validation
    if not username or not password:
        print("Registration failed: Username and password cannot be empty.")
        return
    
    if username in user_database:
        print(f"Registration failed: Username '{username}' already exists.")
        return

    # Rule #10: Use a strong, cryptographically secure random number generator for salt
    salt = secrets.token_bytes(SALT_BYTES)
    hashed_pw = hash_password(password, salt)
    
    # Store salt and hash together, encoded to hex for storage
    user_database[username] = f"{salt.hex()}:{hashed_pw.hex()}"
    print(f"User '{username}' registered successfully.")

def login(username: str, password: str) -> str:
    """
    Simulates the login process.
    """
    # Rule #1: Input validation
    if not username or not password:
        return "Redirecting to login page: Invalid input."

    stored_credentials = user_database.get(username)
    if not stored_credentials:
        # To mitigate user enumeration, you might want to perform a dummy hash
        # calculation here to make the response time similar to a valid user.
        # For simplicity, we skip it here but it's a good practice.
        return "Redirecting to login page: Invalid credentials."

    try:
        salt_hex, stored_hash_hex = stored_credentials.split(':')
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(stored_hash_hex)
    except (ValueError, TypeError):
        return "Redirecting to login page: Server error."

    # Hash the provided password with the stored salt
    provided_hash = hash_password(password, salt)

    # Use secrets.compare_digest for constant-time comparison to prevent timing attacks
    if secrets.compare_digest(stored_hash, provided_hash):
        return "Login successful! Redirecting to dashboard page."
    else:
        return "Redirecting to login page: Invalid credentials."

def main():
    """Main function with test cases."""
    # Populate the "database" with a user
    register_user("admin", "S3cureP@ssword!23")
    register_user("testuser", "password123")

    print("\n--- Running Test Cases ---")

    # Test Case 1: Correct credentials
    print("1. Testing with correct credentials (admin):")
    print(f"   Result: {login('admin', 'S3cureP@ssword!23')}")
    
    # Test Case 2: Correct username, incorrect password
    print("\n2. Testing with incorrect password (admin):")
    print(f"   Result: {login('admin', 'wrongpassword')}")
    
    # Test Case 3: Incorrect username
    print("\n3. Testing with incorrect username:")
    print(f"   Result: {login('unknownuser', 'S3cureP@ssword!23')}")

    # Test Case 4: Correct username, empty password
    print("\n4. Testing with empty password:")
    print(f"   Result: {login('admin', '')}")

    # Test Case 5: Empty username
    print("\n5. Testing with empty username:")
    print(f"   Result: {login('', 'S3cureP@ssword!23')}")

if __name__ == "__main__":
    main()