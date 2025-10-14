import secrets
import os

# Simulates server-side session storage (session_id -> csrf_token)
_session_storage = {}

def generate_csrf_token():
    """Generates a secure, random token."""
    return secrets.token_hex(16)

def store_token_in_session(session_id, token):
    """Stores the CSRF token in the simulated session."""
    _session_storage[session_id] = token

def validate_csrf_token(session_id, received_token):
    """
    Validates the received token against the one stored in the session.
    Uses secrets.compare_digest for constant-time comparison to mitigate timing attacks.
    """
    if not received_token or not session_id:
        return False
    
    stored_token = _session_storage.get(session_id)
    if not stored_token:
        return False
        
    return secrets.compare_digest(stored_token, received_token)

def process_request(session_id, received_token):
    """Simulates processing a protected action."""
    print(f"Processing request for session: {session_id} with token: {received_token}")
    if validate_csrf_token(session_id, received_token):
        print("SUCCESS: CSRF token is valid. Action allowed.")
    else:
        print("FAILURE: CSRF token is invalid or missing. Action rejected.")
    print("-------------------------------------------------")

def main():
    # --- Test Case 1: Valid Request ---
    print("Test Case 1: Valid Request")
    session_id1 = "user_session_abc123"
    token1 = generate_csrf_token()
    store_token_in_session(session_id1, token1)
    # User submits the form with the correct token
    process_request(session_id1, token1)

    # --- Test Case 2: Invalid/Incorrect Token ---
    print("Test Case 2: Invalid/Incorrect Token")
    session_id2 = "user_session_def456"
    token2 = generate_csrf_token()
    store_token_in_session(session_id2, token2)
    # Attacker tries to submit the form with a guessed/wrong token
    process_request(session_id2, "wrong_token_-_")
    
    # --- Test Case 3: Missing Token ---
    print("Test Case 3: Missing Token")
    session_id3 = "user_session_ghi789"
    token3 = generate_csrf_token()
    store_token_in_session(session_id3, token3)
    # Attacker's request is missing the token
    process_request(session_id3, None)

    # --- Test Case 4: No Token in Session ---
    print("Test Case 4: No Token in Session")
    session_id4 = "user_session_jkl012"
    # No token is generated or stored for this session
    # A request comes in with some token
    process_request(session_id4, "some_random_token")

    # --- Test Case 5: Token Mismatch between Users ---
    print("Test Case 5: Token Mismatch between Users")
    userA_session_id = "user_A_session"
    userA_token = generate_csrf_token()
    store_token_in_session(userA_session_id, userA_token)
    
    userB_session_id = "user_B_session"
    userB_token = generate_csrf_token()
    store_token_in_session(userB_session_id, userB_token)

    print("Attacker tries to use User B's token for User A's session:")
    # Attacker on a different session tries to use User B's token to attack User A
    process_request(userA_session_id, userB_token)

if __name__ == "__main__":
    main()