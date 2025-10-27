
import hashlib
import secrets
import re
from typing import Optional, Dict

# Email validation pattern - RFC 5322 simplified
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$')

# Security constants
MIN_PASSWORD_LENGTH = 8
SALT_LENGTH = 16
PBKDF2_ITERATIONS = 210000

# In-memory stores (in production, use secure database)
user_store: Dict[str, dict] = {}
session_store: Dict[str, str] = {}


def hash_password(password: str, salt: bytes) -> bytes:
    """\n    Securely hash password using PBKDF2-HMAC-SHA-256 with unique salt.\n    Uses 210,000 iterations to meet security requirements.\n    """
    if not isinstance(password, str) or not isinstance(salt, bytes):
        raise ValueError("Invalid input types")
    
    # Use PBKDF2-HMAC-SHA-256 for key derivation
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)


def generate_salt() -> bytes:
    """Generate cryptographically secure random salt using secrets module."""
    return secrets.token_bytes(SALT_LENGTH)


def is_valid_email(email: str) -> bool:
    """Validate email format and length."""
    if not email or len(email) > 254:
        return False
    return EMAIL_PATTERN.match(email) is not None


def is_valid_password(password: str) -> bool:
    """\n    Validate password strength requirements:\n    - Minimum 8 characters\n    - Contains uppercase letter\n    - Contains lowercase letter\n    - Contains digit\n    """
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False
    
    has_digit = any(c.isdigit() for c in password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    
    return has_digit and has_lower and has_upper


def register_user(email: str, password: str) -> str:
    """Register a new user with email and password."""
    # Validate input parameters
    if not email or not password:
        return "Error: Invalid input"
    
    if not is_valid_email(email):
        return "Error: Invalid email format"
    
    if not is_valid_password(password):
        return f"Error: Password must be at least {MIN_PASSWORD_LENGTH} characters and contain uppercase, lowercase, and digit"
    
    # Check if user already exists
    if email in user_store:
        return "Error: User already exists"
    
    # Generate unique salt for this user (mitigates CWE-759)
    salt = generate_salt()
    
    # Hash password with salt
    password_hash = hash_password(password, salt)
    
    # Store user account
    user_store[email] = {
        'email': email,
        'password_hash': password_hash,
        'salt': salt
    }
    
    return "Success: User registered"


def login(email: str, password: str) -> Optional[str]:
    """Authenticate user and create session token."""
    # Validate input parameters
    if not email or not password:
        return None
    
    # Retrieve user account
    account = user_store.get(email)
    if not account:
        return None  # User not found - generic error to prevent enumeration
    
    # Hash provided password with stored salt
    provided_hash = hash_password(password, account['salt'])
    
    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(provided_hash, account['password_hash']):
        return None  # Invalid password - generic error
    
    # Generate secure session token using CSPRNG
    session_token = secrets.token_urlsafe(32)
    
    # Store session
    session_store[session_token] = email
    
    return session_token


def get_email_from_session(session_token: str) -> Optional[str]:
    """Validate session token and return associated email."""
    if not session_token:
        return None
    return session_store.get(session_token)


def change_email(session_token: str, old_email: str, new_email: str, password: str) -> str:
    """\n    Change user email after authentication.\n    Requires valid session, correct old email, and password confirmation.\n    """
    # Validate all input parameters
    if not session_token or not old_email or not new_email or not password:
        return "Error: Invalid input"
    
    # Verify session is valid (user must be logged in)
    session_email = get_email_from_session(session_token)
    if not session_email:
        return "Error: Not authenticated"
    
    # Verify old email matches session email
    if session_email != old_email:
        return "Error: Email mismatch"
    
    # Validate new email format
    if not is_valid_email(new_email):
        return "Error: Invalid new email format"
    
    # Check if new email is already taken by another user
    if new_email in user_store and new_email != old_email:
        return "Error: Email already in use"
    
    # Retrieve user account
    account = user_store.get(old_email)
    if not account:
        return "Error: User not found"
    
    # Verify password using constant-time comparison
    provided_hash = hash_password(password, account['salt'])
    if not secrets.compare_digest(provided_hash, account['password_hash']):
        return "Error: Invalid password"
    
    # Update email in user store
    del user_store[old_email]
    account['email'] = new_email
    user_store[new_email] = account
    
    # Update session
    session_store[session_token] = new_email
    
    return "Success: Email changed"


def main():
    print("=== Test Case 1: Register and change email successfully ===")
    result1 = register_user("user1@example.com", "SecurePass123")
    print(f"Register: {result1}")
    token1 = login("user1@example.com", "SecurePass123")
    print(f"Login: {'Success' if token1 else 'Failed'}")
    change1 = change_email(token1, "user1@example.com", "newemail1@example.com", "SecurePass123")
    print(f"Change email: {change1}")
    print()
    
    print("=== Test Case 2: Wrong old email ===")
    result2 = register_user("user2@example.com", "StrongPass456")
    print(f"Register: {result2}")
    token2 = login("user2@example.com", "StrongPass456")
    change2 = change_email(token2, "wrong@example.com", "new2@example.com", "StrongPass456")
    print(f"Change email with wrong old email: {change2}")
    print()
    
    print("=== Test Case 3: Wrong password ===")
    result3 = register_user("user3@example.com", "MyPassword789")
    print(f"Register: {result3}")
    token3 = login("user3@example.com", "MyPassword789")
    change3 = change_email(token3, "user3@example.com", "new3@example.com", "WrongPass123")
    print(f"Change email with wrong password: {change3}")
    print()
    
    print("=== Test Case 4: Not logged in ===")
    change4 = change_email("invalid_token", "user4@example.com", "new4@example.com", "AnyPass123")
    print(f"Change email without login: {change4}")
    print()
    
    print("=== Test Case 5: Invalid new email format ===")
    result5 = register_user("user5@example.com", "ValidPass999")
    print(f"Register: {result5}")
    token5 = login("user5@example.com", "ValidPass999")
    change5 = change_email(token5, "user5@example.com", "invalid-email", "ValidPass999")
    print(f"Change to invalid email: {change5}")


if __name__ == "__main__":
    main()
