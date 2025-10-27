
import hashlib
import secrets
import time
from typing import Dict, Optional, Tuple

# Secure storage for user credentials (hashed passwords with unique salts)
# In production, use a proper database with encrypted storage
user_database: Dict[str, Dict] = {}

MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_TIME_SECONDS = 300  # 5 minutes

def generate_salt() -> bytes:
    """Generate cryptographically secure random salt using secrets module"""
    return secrets.token_bytes(16)  # 128-bit salt

def hash_password(password: str, salt: bytes) -> bytes:
    """Hash password with unique salt using SHA-256 and multiple iterations"""
    # Use UTF-8 encoding for consistent hashing
    pwd_bytes = password.encode('utf-8')
    
    # Combine salt and password
    hash_obj = hashlib.sha256(salt + pwd_bytes)
    hashed = hash_obj.digest()
    
    # Multiple iterations to slow down brute force attacks
    for _ in range(10000):
        hash_obj = hashlib.sha256(hashed)
        hashed = hash_obj.digest()
    
    return hashed

def add_user(username: str, password: str) -> None:
    """Add user to database with hashed password and unique salt"""
    # Input validation - reject None or empty values
    if not username or not password:
        raise ValueError("Username and password cannot be empty")
    
    # Validate username format (alphanumeric only, max 50 chars)
    if not username.isalnum() or len(username) > 50:
        raise ValueError("Invalid username format")
    
    # Generate unique salt for this user
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    
    user_database[username] = {
        'password_hash': password_hash,
        'salt': salt,
        'failed_attempts': 0,
        'lockout_until': 0
    }

def verify_password(username: str, password: str) -> bool:
    """Verify password using constant-time comparison to prevent timing attacks"""
    # Input validation
    if not username or not password:
        return False
    
    user = user_database.get(username)
    
    if user is None:
        # Perform dummy hash to prevent timing attacks
        dummy_salt = secrets.token_bytes(16)
        hash_password(password, dummy_salt)
        return False
    
    # Check if account is locked
    if user['lockout_until'] > time.time():
        return False
    
    # Hash provided password with stored salt
    provided_hash = hash_password(password, user['salt'])
    
    # Constant-time comparison using secrets.compare_digest
    matches = secrets.compare_digest(provided_hash, user['password_hash'])
    
    if matches:
        # Reset failed attempts on success
        user['failed_attempts'] = 0
        user['lockout_until'] = 0
    else:
        # Increment failed attempts
        user['failed_attempts'] += 1
        if user['failed_attempts'] >= MAX_LOGIN_ATTEMPTS:
            user['lockout_until'] = time.time() + LOCKOUT_TIME_SECONDS
    
    return matches

def redirect_to_session_page(username: str) -> None:
    """Simulate session page redirect"""
    print("Login successful! Redirecting to session page...")
    print(f"Welcome, {username}!")
    # In a real application, create secure session token here
    # using secrets.token_urlsafe() and set appropriate session cookies
    # with HttpOnly, Secure, SameSite flags

def login(username: str, password: str) -> str:
    """Main login function with input validation and security checks"""
    # Input validation - check for None/empty
    if not username or not password:
        return "Invalid username or password"
    
    # Sanitize username input - allow only alphanumeric
    sanitized_username = ''.join(c for c in username if c.isalnum())
    if not sanitized_username or sanitized_username != username:
        return "Invalid username or password"
    
    # Length validation
    if len(username) > 50 or len(password) > 128:
        return "Invalid username or password"
    
    # Check if account is locked
    user = user_database.get(sanitized_username)
    if user and user['lockout_until'] > time.time():
        return "Account temporarily locked due to multiple failed attempts"
    
    # Verify credentials
    if verify_password(sanitized_username, password):
        redirect_to_session_page(sanitized_username)
        return "SUCCESS"
    else:
        # Generic error message to prevent username enumeration
        return "Invalid username or password"

# Initialize with test users (passwords hashed with unique salts)
def initialize_test_users():
    """Initialize database with test users"""
    add_user("admin", "SecurePass123!")
    add_user("user1", "MyPassword456@")
    add_user("testuser", "Test789#Pass")

def main():
    """Main function with test cases"""
    # Initialize test users
    initialize_test_users()
    
    print("=== Secure Login System Test Cases ===\\n")
    
    # Test case 1: Valid login
    print("Test 1: Valid credentials (admin/SecurePass123!)")
    result1 = login("admin", "SecurePass123!")
    print(f"Result: {result1}\\n")
    
    # Test case 2: Invalid password
    print("Test 2: Invalid password")
    result2 = login("admin", "WrongPassword")
    print(f"Result: {result2}\\n")
    
    # Test case 3: Non-existent user
    print("Test 3: Non-existent user")
    result3 = login("nonexistent", "password")
    print(f"Result: {result3}\\n")
    
    # Test case 4: Empty credentials
    print("Test 4: Empty username")
    result4 = login("", "password")
    print(f"Result: {result4}\\n")
    
    # Test case 5: Valid login for another user
    print("Test 5: Valid credentials (user1/MyPassword456@)")
    result5 = login("user1", "MyPassword456@")
    print(f"Result: {result5}\\n")

if __name__ == "__main__":
    main()
