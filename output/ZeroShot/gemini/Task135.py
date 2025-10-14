import secrets
import hmac

# Simulates a server-side session store (e.g., in-memory, Redis, etc.)
# Maps Session ID -> CSRF Token
SESSION_STORE = {}

def generate_csrf_token(session_id: str) -> str:
    """
    Simulates a user requesting a page with a form.
    The server generates a CSRF token, stores it in the user's session,
    and sends it to the client to be included in the form.
    
    :param session_id: The user's session identifier.
    :return: The generated CSRF token.
    """
    if not session_id:
        raise ValueError("Session ID cannot be empty.")
    
    token = secrets.token_hex(32)
    SESSION_STORE[session_id] = token
    return token

def validate_csrf_token(session_id: str, submitted_token: str) -> bool:
    """
    Simulates a form submission from a user.
    The server validates the submitted token against the one stored in the session.

    :param session_id: The user's session identifier.
    :param submitted_token: The CSRF token received from the submitted form.
    :return: True if the token is valid, False otherwise.
    """
    if not session_id or not submitted_token:
        return False
        
    stored_token = SESSION_STORE.get(session_id)
    if not stored_token:
        return False # No session or token found for this user

    # Use hmac.compare_digest for a constant-time comparison to prevent timing attacks
    return hmac.compare_digest(stored_token, submitted_token)

def main():
    """Main function with test cases."""
    print("--- CSRF Protection Simulation ---")

    user1_session_id = "session_abc_123"
    user2_session_id = "session_xyz_789"

    # Test Case 1: Valid request
    print("\n--- Test Case 1: Valid Request ---")
    user1_token = generate_csrf_token(user1_session_id)
    print(f"User 1 generated token: {user1_token}")
    is_valid1 = validate_csrf_token(user1_session_id, user1_token)
    print(f"Form submission with correct token is valid: {is_valid1}")
    assert is_valid1

    # Test Case 2: Invalid request (wrong token)
    print("\n--- Test Case 2: Invalid Request (Wrong Token) ---")
    attacker_token = "fake_malicious_token"
    print(f"User 1 submitting with a wrong token: {attacker_token}")
    is_valid2 = validate_csrf_token(user1_session_id, attacker_token)
    print(f"Form submission with wrong token is valid: {is_valid2}")
    assert not is_valid2

    # Test Case 3: Invalid request (missing token)
    print("\n--- Test Case 3: Invalid Request (Missing Token) ---")
    is_valid3 = validate_csrf_token(user1_session_id, "")
    print(f"Form submission with missing token is valid: {is_valid3}")
    assert not is_valid3

    # Test Case 4: Invalid request (token from a different user's session)
    print("\n--- Test Case 4: Invalid Request (Token from another session) ---")
    user2_token = generate_csrf_token(user2_session_id)
    print(f"User 2 generated token: {user2_token}")
    print("User 1 attempts to submit form with User 2's token.")
    is_valid4 = validate_csrf_token(user1_session_id, user2_token)
    print(f"Submission is valid: {is_valid4}")
    assert not is_valid4

    # Test Case 5: Valid request after token regeneration (e.g., user logs in again)
    print("\n--- Test Case 5: Valid Request after Token Regeneration ---")
    print(f"User 1 old token: {user1_token}")
    user1_new_token = generate_csrf_token(user1_session_id)  # Token is regenerated
    print(f"User 1 new token: {user1_new_token}")
    is_valid5_old = validate_csrf_token(user1_session_id, user1_token)  # Old token is now invalid
    is_valid5_new = validate_csrf_token(user1_session_id, user1_new_token)  # New token is valid
    print(f"Submission with old token is valid: {is_valid5_old}")
    print(f"Submission with new token is valid: {is_valid5_new}")
    assert not is_valid5_old
    assert is_valid5_new

if __name__ == "__main__":
    main()