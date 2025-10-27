import hashlib
import secrets
import re
import os

# In-memory database simulation
user_database = {}

# Constants for password hashing
# Iteration count should be high. OWASP recommends at least 310,000 for PBKDF2-SHA256.
ITERATIONS = 310000
SALT_BYTES = 16
HASH_BYTES = 32
HASHING_ALGORITHM = 'sha256'

# Regex for basic input validation
# Username: 3-20 chars, alphanumeric and underscores
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
# Password: 8-100 chars, at least one uppercase, one lowercase, one digit, one special char
PASSWORD_REGEX = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,100}$")

def hash_password(password: str) -> str:
    """
    Hashes a password using PBKDF2 with a cryptographically secure random salt.

    Args:
        password: The plaintext password string.

    Returns:
        A formatted string containing the algorithm, iterations, salt (hex), and hash (hex).
    """
    # Rule #9 & #10: Use a unique, unpredictable salt
    salt = secrets.token_bytes(SALT_BYTES)
    
    # Rule #8: Use a strong key derivation function
    key = hashlib.pbkdf2_hmac(
        HASHING_ALGORITHM,
        password.encode('utf-8'),
        salt,
        ITERATIONS,
        dklen=HASH_BYTES
    )
    
    # Store parameters with the hash for future verification
    return f"pbkdf2_{HASHING_ALGORITHM}:{ITERATIONS}:{salt.hex()}:{key.hex()}"

def register_user(username: str, password: str) -> bool:
    """
    Registers a new user after validating inputs and hashing the password.

    Args:
        username: The username for the new account.
        password: The plaintext password for the new account.

    Returns:
        True if registration is successful, False otherwise.
    """
    # Rule #1: Input validation
    if not isinstance(username, str) or not USERNAME_REGEX.match(username):
        print("Registration failed: Invalid username format.")
        return False
    if not isinstance(password, str) or not PASSWORD_REGEX.match(password):
        print("Registration failed: Password does not meet policy requirements.")
        return False
        
    if username in user_database:
        print(f"Registration failed: Username '{username}' already exists.")
        return False

    try:
        hashed_password = hash_password(password)
        user_database[username] = hashed_password
        print(f"User '{username}' registered successfully.")
        return True
    except Exception as e:
        print(f"An unexpected error occurred during registration: {e}")
        return False

if __name__ == "__main__":
    print("--- User Registration Simulation ---")
    
    # Test Case 1: Successful registration
    register_user("alice_123", "ValidPass1!")

    # Test Case 2: Successful registration with another user
    register_user("bob_smith", "Another_Good_P@ssw0rd")

    # Test Case 3: Failed registration - duplicate username
    register_user("alice_123", "SomeOtherPass1?")

    # Test Case 4: Failed registration - invalid username
    register_user("!!invalid-user!!", "ValidPass1!")

    # Test Case 5: Failed registration - weak password
    register_user("charlie", "weak")
    
    print("\n--- Simulated User Database ---")
    for username, hashed_info in user_database.items():
        print(f"Username: {username}\nStored Hash: {hashed_info}\n")