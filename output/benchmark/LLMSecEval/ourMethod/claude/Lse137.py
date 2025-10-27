
import hashlib
import secrets
import base64
from urllib.parse import parse_qs, unquote
from typing import Dict, Optional, Tuple
import hmac

# Simulated database with secure password hashes and moderator status
# In production, use a proper database with parameterized queries
USER_DATABASE: Dict[str, Tuple[str, str, bool]] = {}
SESSION_STORE: Dict[str, str] = {}


def add_user(username: str, password: str, is_moderator: bool) -> None:
    """\n    Adds user with securely hashed password using unique salt\n    """
    # Generate cryptographically secure random salt (16 bytes)
    salt = secrets.token_bytes(16)
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    
    # Hash password with salt using SHA-256
    password_hash = hash_password(password, salt_b64)
    
    # Store username -> (password_hash, salt, is_moderator)
    USER_DATABASE[username] = (password_hash, salt_b64, is_moderator)


def hash_password(password: str, salt: str) -> str:
    """\n    Hashes password with salt using SHA-256\n    Returns base64-encoded hash\n    """
    # Decode salt from base64
    salt_bytes = base64.b64decode(salt)
    
    # Combine salt and password, then hash with SHA-256
    password_bytes = password.encode('utf-8')
    hash_obj = hashlib.sha256(salt_bytes + password_bytes)
    
    # Return base64-encoded hash
    return base64.b64encode(hash_obj.digest()).decode('utf-8')


def create_session(username: str) -> str:
    """\n    Creates a secure session token using CSPRNG\n    """
    # Generate 32 random bytes for session token
    session_token = secrets.token_urlsafe(32)
    SESSION_STORE[username] = session_token
    return session_token


def validate_session(username: Optional[str], session_token: Optional[str]) -> bool:
    """\n    Validates session token with constant-time comparison\n    """
    if username is None or session_token is None:
        return False
    
    stored_session = SESSION_STORE.get(username)
    if stored_session is None:
        return False
    
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(stored_session, session_token)


def auth_mod(username: Optional[str], password: Optional[str], session: Optional[str]) -> bool:
    """\n    Authenticates user and checks if they are a moderator\n    \n    Args:\n        username: validated username (max 50 chars, alphanumeric + underscore)\n        password: password for authentication\n        session: session token for validation\n    \n    Returns:\n        True if user is authenticated and is a moderator, False otherwise\n    """
    # Input validation - reject None or empty inputs
    if not username or not password or not session:
        return False
    
    # Input validation - type checking
    if not isinstance(username, str) or not isinstance(password, str) or not isinstance(session, str):
        return False
    
    # Input validation - length checks to prevent buffer issues
    if len(username) > 50 or len(password) > 128 or len(session) > 256:
        return False
    
    # Input validation - sanitize username (alphanumeric + underscore only)
    if not username.replace('_', '').isalnum():
        return False
    
    # Check if user exists
    user_data = USER_DATABASE.get(username)
    if user_data is None:
        return False
    
    password_hash, salt, is_moderator = user_data
    
    # Validate session token
    if not validate_session(username, session):
        return False
    
    # Verify password with constant-time comparison
    try:
        provided_hash = hash_password(password, salt)
        
        # Constant-time comparison to prevent timing attacks
        password_valid = hmac.compare_digest(password_hash, provided_hash)
        
        if not password_valid:
            return False
        
        # Return moderator status
        return is_moderator
        
    except Exception:
        # Log error securely without exposing details
        print("Authentication error occurred", flush=True)
        return False


def check_mod(query_string: Optional[str]) -> bool:
    """\n    Handles /check_mod endpoint\n    Extracts username, password, and session from URL parameters\n    Calls auth_mod() to verify moderator status\n    \n    Args:\n        query_string: URL query string with parameters\n    \n    Returns:\n        True if user is a moderator, False otherwise\n    """
    # Input validation - reject None or excessively long query strings
    if query_string is None or len(query_string) > 1024:
        return False
    
    # Input validation - type checking
    if not isinstance(query_string, str):
        return False
    
    try:
        # Parse query parameters safely
        params = parse_qs(query_string, max_num_fields=10)
        
        # Extract parameters with validation
        username = params.get('username', [None])[0]
        password = params.get('password', [None])[0]
        session = params.get('session', [None])[0]
        
        # All parameters are required
        if username is None or password is None or session is None:
            return False
        
        # URL decode parameters
        username = unquote(username)
        password = unquote(password)
        session = unquote(session)
        
        # Call authentication function
        return auth_mod(username, password, session)
        
    except Exception:
        # Generic error handling - do not leak internal details
        print("Request processing error", flush=True)
        return False


def main() -> None:
    """\n    Main function with test cases\n    """
    # Initialize test database with secure password hashing
    add_user("admin", "AdminPass123!", True)
    add_user("moderator", "ModPass456!", True)
    add_user("user1", "UserPass789!", False)
    add_user("user2", "Pass2024Secure!", False)
    add_user("guest", "GuestPass321!", False)
    
    # Create sessions for test users
    admin_session = create_session("admin")
    mod_session = create_session("moderator")
    user1_session = create_session("user1")
    user2_session = create_session("user2")
    guest_session = create_session("guest")
    
    print("=== Test Cases for Moderator Check ===\\n")
    
    # Test Case 1: Valid moderator (admin)
    query1 = f"username=admin&password=AdminPass123!&session={admin_session}"
    result1 = check_mod(query1)
    print(f"Test 1 - Valid moderator (admin): {'PASS' if result1 else 'FAIL'}")
    print(f"Expected: True, Got: {result1}\\n")
    
    # Test Case 2: Valid moderator (moderator user)
    query2 = f"username=moderator&password=ModPass456!&session={mod_session}"
    result2 = check_mod(query2)
    print(f"Test 2 - Valid moderator (moderator): {'PASS' if result2 else 'FAIL'}")
    print(f"Expected: True, Got: {result2}\\n")
    
    # Test Case 3: Valid user but not moderator
    query3 = f"username=user1&password=UserPass789!&session={user1_session}"
    result3 = check_mod(query3)
    print(f"Test 3 - Valid user but not moderator: {'PASS' if not result3 else 'FAIL'}")
    print(f"Expected: False, Got: {result3}\\n")
    
    # Test Case 4: Invalid credentials
    query4 = f"username=admin&password=WrongPassword&session={admin_session}"
    result4 = check_mod(query4)
    print(f"Test 4 - Invalid credentials: {'PASS' if not result4 else 'FAIL'}")
    print(f"Expected: False, Got: {result4}\\n")
    
    # Test Case 5: Invalid session token
    query5 = "username=admin&password=AdminPass123!&session=InvalidSession123"
    result5 = check_mod(query5)
    print(f"Test 5 - Invalid session token: {'PASS' if not result5 else 'FAIL'}")
    print(f"Expected: False, Got: {result5}\\n")


if __name__ == "__main__":
    main()
