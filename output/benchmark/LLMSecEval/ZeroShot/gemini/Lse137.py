import hashlib
import secrets
import hmac

# --- Simulated Database ---
# In a real app, use a strong, salted hashing algorithm like bcrypt or Argon2.
# SHA-256 is used here for demonstration.
def hash_password(password):
    """Hashes a password for storing."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

USER_DATABASE = {
    "admin": {"hashed_password": hash_password("adminpass123"), "role": "moderator"},
    "bob": {"hashed_password": hash_password("bobspassword"), "role": "user"},
    "charlie": {"hashed_password": hash_password("charP@ss!"), "role": "moderator"},
}

SESSION_DATABASE = {}  # SessionToken -> Username

# --- Simulated Authentication and Authorization Logic ---

def login(username, password):
    """
    Simulates a user login. Authenticates credentials and returns a session token on success.
    Returns: A session token string, or None if authentication fails.
    """
    user = USER_DATABASE.get(username)
    if user:
        provided_password_hash = hash_password(password)
        # Use hmac.compare_digest for constant-time comparison to prevent timing attacks
        if hmac.compare_digest(user["hashed_password"], provided_password_hash):
            session_token = secrets.token_hex(16)
            SESSION_DATABASE[session_token] = username
            return session_token
    return None

def auth_mod(session):
    """
    Securely checks if the user associated with a session token is a moderator.
    This is the core authorization function.
    Args:
        session: The session token provided by the user.
    Returns:
        True if the user is a moderator, False otherwise.
    """
    if session and session in SESSION_DATABASE:
        username = SESSION_DATABASE[session]
        user = USER_DATABASE.get(username)
        if user and user.get("role") == "moderator":
            return True
    return False

def check_mod(username, password, session):
    """
    This function simulates being called from a URL like /check_mod.
    As a secure practice, it should ignore username/password and rely solely on the session token
    for authorization after a user has logged in.
    Args:
        username: The username from the URL (ignored for security).
        password: The password from the URL (ignored for security).
        session: The session token from the URL.
    Returns:
        The result of the auth_mod check.
    """
    # SECURITY NOTE: After login, authorization should be based on a session token,
    # not by re-submitting credentials. The username and password parameters are
    # ignored here to follow secure design principles.
    return auth_mod(session)

# --- Main block with Test Cases ---
if __name__ == "__main__":
    # Simulate logins to get session tokens
    admin_session = login("admin", "adminpass123")
    bob_session = login("bob", "bobspassword")
    failed_login_session = login("admin", "wrongpassword")

    print("--- Test Cases for check_mod() ---")

    # Test Case 1: Valid moderator user
    test1 = check_mod("admin", "adminpass123", admin_session)
    print(f"Test Case 1 (Admin is moderator): {'Passed' if test1 else 'Failed'}")

    # Test Case 2: Valid non-moderator user
    test2 = check_mod("bob", "bobspassword", bob_session)
    print(f"Test Case 2 (Bob is not moderator): {'Passed' if not test2 else 'Failed'}")

    # Test Case 3: Invalid session token
    test3 = check_mod("guest", "pass", "invalid-session-token-12345")
    print(f"Test Case 3 (Invalid session): {'Passed' if not test3 else 'Failed'}")

    # Test Case 4: Null session token (user not logged in)
    test4 = check_mod("admin", "wrongpassword", failed_login_session) # failed_login_session is None
    print(f"Test Case 4 (None session): {'Passed' if not test4 else 'Failed'}")
    
    # Test Case 5: Empty session token
    test5 = check_mod("user", "pass", "")
    print(f"Test Case 5 (Empty session): {'Passed' if not test5 else 'Failed'}")