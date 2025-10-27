
import hashlib
import secrets
import time
from typing import Dict, Any, Optional

# Secure session store
sessions: Dict[str, 'UserSession'] = {}
# User database with hashed passwords and salts
users: Dict[str, 'UserData'] = {}


class UserData:
    """User data with securely hashed password and unique salt"""
    def __init__(self, username: str, password_hash: bytes, salt: bytes, is_admin: bool):
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        self.is_admin = is_admin


class UserSession:
    """User session with expiration"""
    def __init__(self, username: str, is_admin: bool):
        self.username = username
        self.is_admin = is_admin
        # Session expires in 30 minutes
        self.expiry_time = time.time() + (30 * 60)
    
    def is_valid(self) -> bool:
        """Check if session is still valid"""
        return time.time() < self.expiry_time


def hash_password(password: str, salt: bytes) -> bytes:
    """\n    Hash password using PBKDF2-HMAC-SHA-256 with 210000 iterations\n    per security policy to prevent brute force attacks\n    """
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 210000)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def create_user(username: str, password: str, is_admin: bool) -> None:
    """\n    Create user with unique salt per CWE-759 mitigation\n    Uses cryptographically secure random generator for salt\n    """
    # Generate unique 16-byte salt using CSPRNG
    salt = secrets.token_bytes(16)
    password_hash = hash_password(password, salt)
    users[username] = UserData(username, password_hash, salt, is_admin)


# Initialize test users with secure hashing
create_user("user1", "Password123!", False)
create_user("admin1", "AdminPass456!", True)
create_user("user2", "SecurePass789!", False)
create_user("admin2", "AdminSecure000!", True)
create_user("testuser", "TestPass111!", False)


def login(params: Dict[str, str]) -> str:
    """\n    GET /login - Display login form\n    Returns HTML login form\n    """
    return """<html><body>\n    <h2>Login</h2>\n    <form method='POST' action='/do_login'>\n    Username: <input type='text' name='username' required><br>\n    Password: <input type='password' name='password' required><br>\n    <input type='submit' value='Login'>\n    </form></body></html>"""


def do_login(params: Dict[str, str]) -> Dict[str, Any]:
    """\n    POST /do_login - Process login credentials\n    Validates input, verifies password, creates session\n    """
    result: Dict[str, Any] = {}
    
    # Input validation: check required parameters
    username = params.get("username")
    password = params.get("password")
    
    if not username or not username.strip() or not password:
        result["success"] = False
        result["message"] = "Invalid credentials"
        return result
    
    # Sanitize username: limit length and validate format
    username = username.strip()
    if len(username) > 50 or not username.replace('_', '').isalnum():
        result["success"] = False
        result["message"] = "Invalid credentials"
        return result
    
    # Validate password length
    if len(password) > 128:
        result["success"] = False
        result["message"] = "Invalid credentials"
        return result
    
    try:
        # Lookup user
        user_data = users.get(username)
        if user_data is None:
            # Generic error to prevent user enumeration
            result["success"] = False
            result["message"] = "Invalid credentials"
            return result
        
        # Verify password using constant-time comparison
        provided_hash = hash_password(password, user_data.salt)
        if not constant_time_compare(provided_hash, user_data.password_hash):
            result["success"] = False
            result["message"] = "Invalid credentials"
            return result
        
        # Generate secure session token using CSPRNG (secrets module)
        session_token = secrets.token_urlsafe(32)
        session = UserSession(user_data.username, user_data.is_admin)
        sessions[session_token] = session
        
        result["success"] = True
        result["sessionToken"] = session_token
        result["message"] = "Login successful"
        
    except Exception as e:
        # Generic error message, log class name only (not details)
        print(f"Login error: {type(e).__name__}", flush=True)
        result["success"] = False
        result["message"] = "Authentication error"
    
    return result


def index(params: Dict[str, str]) -> str:
    """\n    GET /index - Public home page\n    No authentication required\n    """
    return """<html><body>\n    <h1>Welcome to the Application</h1>\n    <p>This is a public page.</p>\n    <a href='/login'>Login</a>\n    </body></html>"""


def user_page(params: Dict[str, str]) -> Dict[str, Any]:
    """\n    GET /user_page - Authenticated user page\n    Requires valid session token\n    """
    result: Dict[str, Any] = {}
    
    # Validate session token
    session_token = params.get("sessionToken")
    if not session_token or not session_token.strip():
        result["authorized"] = False
        result["message"] = "Authentication required"
        return result
    
    # Check session validity
    session = sessions.get(session_token)
    if session is None or not session.is_valid():
        # Clean up expired session
        if session is not None:
            sessions.pop(session_token, None)
        result["authorized"] = False
        result["message"] = "Session expired or invalid"
        return result
    
    result["authorized"] = True
    result["username"] = session.username
    result["content"] = f"Welcome to your user page, {session.username}!"
    return result


def admin_page(params: Dict[str, str]) -> Dict[str, Any]:
    """\n    GET /admin_page - Admin-only page\n    Requires valid session token with admin privileges\n    """
    result: Dict[str, Any] = {}
    
    # Validate session token
    session_token = params.get("sessionToken")
    if not session_token or not session_token.strip():
        result["authorized"] = False
        result["message"] = "Authentication required"
        return result
    
    # Check session validity
    session = sessions.get(session_token)
    if session is None or not session.is_valid():
        # Clean up expired session
        if session is not None:
            sessions.pop(session_token, None)
        result["authorized"] = False
        result["message"] = "Session expired or invalid"
        return result
    
    # Check admin privilege
    if not session.is_admin:
        result["authorized"] = False
        result["message"] = "Insufficient privileges"
        return result
    
    result["authorized"] = True
    result["username"] = session.username
    result["content"] = f"Welcome to the admin page, {session.username}!"
    return result


if __name__ == "__main__":
    print("=== Test Case 1: Login page (GET) ===")
    login_page = login({})
    print(login_page[:100] + "...")
    
    print("\\n=== Test Case 2: Valid login (POST) ===")
    login_params = {"username": "user1", "password": "Password123!"}
    login_result = do_login(login_params)
    print(f"Success: {login_result['success']}")
    session_token = login_result.get("sessionToken")
    print(f"Session token: {'Generated' if session_token else 'None'}")
    
    print("\\n=== Test Case 3: Invalid login ===")
    invalid_params = {"username": "user1", "password": "WrongPassword!"}
    invalid_result = do_login(invalid_params)
    print(f"Success: {invalid_result['success']}")
    print(f"Message: {invalid_result['message']}")
    
    print("\\n=== Test Case 4: User page access ===")
    if session_token:
        user_params = {"sessionToken": session_token}
        user_result = user_page(user_params)
        print(f"Authorized: {user_result['authorized']}")
        print(f"Content: {user_result['content']}")
    
    print("\\n=== Test Case 5: Admin page access (user) ===")
    if session_token:
        admin_params = {"sessionToken": session_token}
        admin_result = admin_page(admin_params)
        print(f"Authorized: {admin_result['authorized']}")
        print(f"Message: {admin_result['message']}")
    
    print("\\n=== Bonus: Admin login and access ===")
    admin_login_params = {"username": "admin1", "password": "AdminPass456!"}
    admin_login_result = do_login(admin_login_params)
    admin_token = admin_login_result.get("sessionToken")
    if admin_token:
        admin_access_params = {"sessionToken": admin_token}
        admin_access_result = admin_page(admin_access_params)
        print(f"Admin authorized: {admin_access_result['authorized']}")
        print(f"Admin content: {admin_access_result['content']}")
