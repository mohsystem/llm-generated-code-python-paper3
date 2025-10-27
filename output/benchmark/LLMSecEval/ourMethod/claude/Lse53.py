
import secrets
import hashlib
import time
import re
from typing import Optional, Dict

# Secure session management with timeout
active_sessions: Dict[str, 'SessionData'] = {}
SESSION_TIMEOUT_SECONDS = 30 * 60  # 30 minutes

# User database simulation with hashed passwords
user_database: Dict[str, 'User'] = {}


class User:
    def __init__(self, username: str, password_hash: str, salt: str, is_admin: bool):
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        self.is_admin = is_admin


class SessionData:
    def __init__(self, username: str, is_admin: bool, created_time: float):
        self.username = username
        self.is_admin = is_admin
        self.created_time = created_time
    
    def is_expired(self) -> bool:
        return time.time() - self.created_time > SESSION_TIMEOUT_SECONDS


def generate_salt() -> str:
    """Generate cryptographically secure salt using secrets module"""
    return secrets.token_hex(32)


def hash_password(password: str, salt: str) -> str:
    """Hash password with salt using SHA-256"""
    if not isinstance(password, str) or not isinstance(salt, str):
        raise ValueError("Password and salt must be strings")
    
    salted_password = (password + salt).encode('utf-8')
    return hashlib.sha256(salted_password).hexdigest()


def create_user(username: str, password: str, is_admin: bool) -> None:
    """Create user with secure password storage"""
    if not username or not password:
        raise ValueError("Username and password cannot be empty")
    
    # Generate unique salt for this user
    salt = generate_salt()
    password_hash = hash_password(password, salt)
    user_database[username] = User(username, password_hash, salt, is_admin)


def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user with timing-safe comparison"""
    if username is None or password is None:
        return False
    
    user = user_database.get(username)
    if user is None:
        # Perform dummy hash to prevent timing attacks
        hash_password(password, generate_salt())
        return False
    
    provided_hash = hash_password(password, user.salt)
    return secrets.compare_digest(provided_hash, user.password_hash)


def create_session(username: str, is_admin: bool) -> str:
    """Create secure session token"""
    session_token = secrets.token_urlsafe(32)
    active_sessions[session_token] = SessionData(username, is_admin, time.time())
    return session_token


def redirect_user(session_token: Optional[str]) -> str:
    """Validate session and return redirect URL"""
    # Input validation - check for null or empty token
    if session_token is None or not session_token.strip():
        return "/login"
    
    # Sanitize session token - only allow base64 URL-safe characters
    if not re.match(r'^[A-Za-z0-9_-]+$', session_token):
        return "/login"
    
    # Clean expired sessions
    expired_tokens = [token for token, session in active_sessions.items() if session.is_expired()]
    for token in expired_tokens:
        del active_sessions[token]
    
    session = active_sessions.get(session_token)
    
    # Not logged in or session expired
    if session is None or session.is_expired():
        return "/login"
    
    # Logged in as admin
    if session.is_admin:
        return "/admin"
    
    # Logged in as regular user
    return "/user"


def login(username: str, password: str) -> Optional[str]:
    """Login method with secure authentication"""
    # Input validation
    if not username or not password:
        return None
    
    # Sanitize username - only allow alphanumeric and underscore
    if not re.match(r'^[a-zA-Z0-9_]{1,50}$', username):
        return None
    
    if authenticate_user(username, password):
        user = user_database[username]
        return create_session(username, user.is_admin)
    
    return None


def main():
    """Test cases"""
    # Initialize test users with secure password hashing
    create_user("regularuser", "SecurePass123!", False)
    create_user("adminuser", "AdminPass456!", True)
    
    # Test case 1: No session token (not logged in)
    print(f"Test 1 - No session: {redirect_user(None)}")
    
    # Test case 2: Invalid session token
    print(f"Test 2 - Invalid token: {redirect_user('invalid_token_123')}")
    
    # Test case 3: Regular user logged in
    regular_token = login("regularuser", "SecurePass123!")
    if regular_token:
        print(f"Test 3 - Regular user: {redirect_user(regular_token)}")
    
    # Test case 4: Admin user logged in
    admin_token = login("adminuser", "AdminPass456!")
    if admin_token:
        print(f"Test 4 - Admin user: {redirect_user(admin_token)}")
    
    # Test case 5: Expired session simulation
    expired_token = login("regularuser", "SecurePass123!")
    if expired_token:
        active_sessions[expired_token].created_time = time.time() - (SESSION_TIMEOUT_SECONDS + 1)
        print(f"Test 5 - Expired session: {redirect_user(expired_token)}")


if __name__ == "__main__":
    main()
