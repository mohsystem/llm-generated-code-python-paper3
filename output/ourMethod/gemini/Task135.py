import secrets
import os

class CsrfProtector:
    """
    A simple CSRF protection manager using the synchronizer token pattern.
    In a real web application, tokens would be stored in the user's session.
    This implementation simulates that with a dictionary.
    """

    def __init__(self):
        # The session store maps session IDs to CSRF tokens.
        self.session_store = {}
        # The number of bytes of randomness for the token
        self.token_byte_length = 32

    def generate_token_for_session(self, session_id: str) -> str:
        """
        Generates a new, cryptographically secure token, stores it associated with
        the session ID, and returns the URL-safe string token.

        :param session_id: A unique identifier for the user's session.
        :return: A URL-safe CSRF token string.
        """
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("Session ID must be a non-empty string")
        
        token = secrets.token_urlsafe(self.token_byte_length)
        self.session_store[session_id] = token
        return token

    def validate_token(self, session_id: str, submitted_token: str) -> bool:
        """
        Validates a submitted token against the one stored for the session.
        Uses a constant-time comparison to prevent timing attacks.

        :param session_id: The user's session identifier.
        :param submitted_token: The token received from the client.
        :return: True if the token is valid, False otherwise.
        """
        if not session_id or not submitted_token:
            return False

        stored_token = self.session_store.get(session_id)
        if stored_token is None:
            return False

        return secrets.compare_digest(stored_token, submitted_token)

    def remove_token(self, session_id: str):
        """
        Removes a token from the store, typically done on session invalidation.
        :param session_id: The user's session identifier.
        """
        self.session_store.pop(session_id, None)

def main():
    """Main function with test cases."""
    csrf_protector = CsrfProtector()
    session_id1 = "user_session_abc123"
    session_id2 = "user_session_def456"

    print("--- Running CSRF Protection Test Cases ---")

    # Test Case 1: Valid token
    print("\n--- Test Case 1: Valid Token ---")
    token1 = csrf_protector.generate_token_for_session(session_id1)
    print(f"Generated Token for {session_id1}: {token1}")
    is_valid1 = csrf_protector.validate_token(session_id1, token1)
    print(f"Validation result: {'PASS' if is_valid1 else 'FAIL'}")
    assert is_valid1

    # Test Case 2: Invalid token
    print("\n--- Test Case 2: Invalid Token ---")
    generated_token2 = csrf_protector.generate_token_for_session(session_id1)
    print(f"Generated Token for {session_id1}: {generated_token2}")
    wrong_token = "invalid_token_this_is_wrong_" + secrets.token_urlsafe(16)
    is_valid2 = csrf_protector.validate_token(session_id1, wrong_token)
    print(f"Validation with wrong token result: {'PASS' if not is_valid2 else 'FAIL'}")
    assert not is_valid2

    # Test Case 3: Missing token in session
    print("\n--- Test Case 3: Missing Token in Session ---")
    is_valid3 = csrf_protector.validate_token("non_existent_session", "some_token")
    print(f"Validation for non-existent session: {'PASS' if not is_valid3 else 'FAIL'}")
    assert not is_valid3

    # Test Case 4: Null/empty submitted token
    print("\n--- Test Case 4: Null/Empty Submitted Token ---")
    generated_token4 = csrf_protector.generate_token_for_session(session_id1)
    print(f"Generated Token for {session_id1}: {generated_token4}")
    is_valid4a = csrf_protector.validate_token(session_id1, "")
    print(f"Validation with empty token: {'PASS' if not is_valid4a else 'FAIL'}")
    assert not is_valid4a

    # Test Case 5: Token from a different session
    print("\n--- Test Case 5: Token from a Different Session ---")
    token_for_session1 = csrf_protector.generate_token_for_session(session_id1)
    token_for_session2 = csrf_protector.generate_token_for_session(session_id2)
    print(f"Token for {session_id1}: {token_for_session1}")
    print(f"Token for {session_id2}: {token_for_session2}")
    is_valid5 = csrf_protector.validate_token(session_id1, token_for_session2)
    print(f"Validating session 1 with session 2's token: {'PASS' if not is_valid5 else 'FAIL'}")
    assert not is_valid5

    print("\n--- All test cases completed ---")

if __name__ == "__main__":
    main()