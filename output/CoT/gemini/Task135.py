import secrets
import os

# Simulates a server-side session store, mapping session IDs to CSRF tokens.
_session_store = {}

def generate_csrf_token():
    """
    Generates a cryptographically secure, random CSRF token.
    :return: A URL-safe, Base64-encoded CSRF token string.
    """
    return secrets.token_urlsafe(32)

def store_token(session_id: str, token: str):
    """
    Stores the CSRF token in the simulated session store.
    :param session_id: The user's session identifier.
    :param token: The CSRF token to store.
    """
    _session_store[session_id] = token

def validate_csrf_token(session_id: str, received_token: str) -> bool:
    """
    Validates a received CSRF token against the one stored in the session
    using a constant-time comparison to mitigate timing attacks.
    :param session_id: The user's session identifier.
    :param received_token: The token received from the client request.
    :return: True if the token is valid, False otherwise.
    """
    stored_token = _session_store.get(session_id)
    if not stored_token or not received_token:
        return False
    
    return secrets.compare_digest(stored_token, received_token)

if __name__ == '__main__':
    # --- Test Cases ---
    session_id1 = "user_session_abc123"
    session_id2 = "user_session_def456"

    # Test Case 1: Successful Validation
    print("--- Test Case 1: Successful Validation ---")
    token1 = generate_csrf_token()
    store_token(session_id1, token1)
    print(f"Generated Token: {token1}")
    print(f"Is token valid? {validate_csrf_token(session_id1, token1)}\n")

    # Test Case 2: Failed Validation (Incorrect Token)
    print("--- Test Case 2: Failed Validation (Incorrect Token) ---")
    correct_token = generate_csrf_token()
    store_token(session_id2, correct_token)
    incorrect_token = "this_is_a_wrong_token"
    print(f"Stored Token: {correct_token}")
    print(f"Submitted Token: {incorrect_token}")
    print(f"Is token valid? {validate_csrf_token(session_id2, incorrect_token)}\n")

    # Test Case 3: Failed Validation (No Token in Session)
    print("--- Test Case 3: Failed Validation (No Token in Session) ---")
    non_existent_session_id = "non_existent_session_xyz789"
    submitted_token = generate_csrf_token()
    print(f"Submitted Token: {submitted_token}")
    print(f"Is token for non-existent session valid? {validate_csrf_token(non_existent_session_id, submitted_token)}\n")

    # Test Case 4: Failed Validation (Submitted Token is None)
    print("--- Test Case 4: Failed Validation (Submitted Token is None) ---")
    print(f"Is None token valid? {validate_csrf_token(session_id1, None)}\n")

    # Test Case 5: Token Re-generation and Validation
    print("--- Test Case 5: Token Re-generation and Validation ---")
    old_token = _session_store.get(session_id1)
    new_token = generate_csrf_token()
    store_token(session_id1, new_token)
    print(f"Old token: {old_token}")
    print(f"New token: {new_token}")
    print(f"Is old token still valid? {validate_csrf_token(session_id1, old_token)}")
    print(f"Is new token valid? {validate_csrf_token(session_id1, new_token)}")