import hashlib
import os
import hmac

# In-memory user store to simulate a database.
# In a real application, this would be a database.
# The structure is { 'username': {'salt': b'...', 'hash': b'...'} }
_user_database = {}

# Security parameters for PBKDF2
_ITERATIONS = 65536
_KEY_LENGTH = 32  # 32 bytes = 256 bits
_HASH_ALGORITHM = 'sha256'

def _hash_password(password: str, salt: bytes) -> bytes:
    """Hashes the password using PBKDF2 with the given salt."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    if not isinstance(salt, bytes) or not salt:
        raise ValueError("Salt must be non-empty bytes.")
        
    pwd_hash = hashlib.pbkdf2_hmac(
        _HASH_ALGORITHM,
        password.encode('utf-8'),
        salt,
        _ITERATIONS,
        dklen=_KEY_LENGTH
    )
    return pwd_hash

def _register_user(username: str, password: str):
    """
    Simulates user registration. Generates a salt, hashes the password,
    and stores the user data.
    """
    if not username or not password:
        print("Registration failed: Username and password cannot be empty.")
        return
    
    # Generate a cryptographically secure random salt
    salt = os.urandom(16)
    hashed_password = _hash_password(password, salt)
    
    # Store username in lowercase for case-insensitive lookup
    _user_database[username.lower()] = {
        'salt': salt,
        'hash': hashed_password
    }

def login(username: str, password: str) -> str:
    """
    Simulates a login attempt, securely checking credentials.

    Args:
        username: The username provided by the user.
        password: The password provided by the user.

    Returns:
        A string indicating the result of the login attempt.
    """
    # Basic input validation
    if not username or not password:
        return "Login failed: Username or password cannot be empty. Redirecting to login page."

    # Retrieve user data (case-insensitive username)
    user_data = _user_database.get(username.lower())
    
    if user_data:
        # Hash the provided password with the user's stored salt
        provided_hash = _hash_password(password, user_data['salt'])
        
        # Compare hashes in a constant-time manner to prevent timing attacks
        if hmac.compare_digest(provided_hash, user_data['hash']):
            return f"Login successful for {username}! Redirecting to dashboard."

    # Generic failure message to prevent username enumeration
    return "Login failed: Invalid username or password. Redirecting to login page."

if __name__ == "__main__":
    # --- Setup: Simulate user registration ---
    _register_user("admin", "AdminPassword123!")
    _register_user("jdoe", "P@ssw0rd_jdoe")
    print("--- User database initialized ---")
    
    # --- Test Cases ---
    print("\n--- Running Test Cases ---")
    
    # Test Case 1: Correct username and password
    print(f"1. {login('admin', 'AdminPassword123!')}")
    
    # Test Case 2: Correct username, incorrect password
    print(f"2. {login('admin', 'WrongPassword')}")
    
    # Test Case 3: Incorrect username
    print(f"3. {login('unknownUser', 'anyPassword')}")
    
    # Test Case 4: Correct username (different case), correct password
    print(f"4. {login('Admin', 'AdminPassword123!')}")
    
    # Test Case 5: Empty password
    print(f"5. {login('jdoe', '')}")
    
    # Test Case 6: Empty username
    print(f"6. {login('', 'P@ssw0rd_jdoe')}")

    # Test Case 7: User exists but with different password case
    print(f"7. {login('jdoe', 'p@ssw0rd_jdoe')}")