
import secrets
import base64
import time
from typing import Dict, Optional, Tuple

class Task135:
    TOKEN_LENGTH = 32
    TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
    
    def __init__(self):
        self.token_store: Dict[str, Tuple[str, float]] = {}
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate a secure CSRF token for the given session."""
        if not session_id or not session_id.strip():
            raise ValueError("Session ID cannot be null or empty")
        
        # Generate cryptographically secure random token
        token_bytes = secrets.token_bytes(self.TOKEN_LENGTH)
        token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
        
        # Store token with expiry time
        expiry_time = time.time() + self.TOKEN_EXPIRY_SECONDS
        self.token_store[session_id] = (token, expiry_time)
        
        return token
    
    def validate_csrf_token(self, session_id: str, token: str) -> bool:
        """Validate the CSRF token for the given session."""
        if not session_id or not session_id.strip():
            return False
        
        if not token or not token.strip():
            return False
        
        # Retrieve stored token
        stored_data = self.token_store.get(session_id)
        if stored_data is None:
            return False
        
        stored_token, expiry_time = stored_data
        
        # Check if token has expired
        if time.time() > expiry_time:
            self.token_store.pop(session_id, None)
            return False
        
        # Use constant-time comparison to prevent timing attacks
        is_valid = self._constant_time_equals(stored_token, token)
        
        # Remove token after validation (one-time use)
        if is_valid:
            self.token_store.pop(session_id, None)
        
        return is_valid
    
    def _constant_time_equals(self, a: str, b: str) -> bool:
        """Compare two strings in constant time to prevent timing attacks."""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0
    
    def invalidate_token(self, session_id: str) -> None:
        """Invalidate the CSRF token for the given session."""
        if session_id:
            self.token_store.pop(session_id, None)


def main():
    print("CSRF Protection Test Cases:")
    print("===========================\\n")
    
    csrf = Task135()
    
    # Test Case 1: Valid token generation and validation
    print("Test Case 1: Valid token generation and validation")
    session1 = "user_session_123"
    token1 = csrf.generate_csrf_token(session1)
    print(f"Generated Token: {token1}")
    result1 = csrf.validate_csrf_token(session1, token1)
    print(f"Validation Result: {result1}")
    print("Expected: True\\n")
    
    # Test Case 2: Invalid token validation
    print("Test Case 2: Invalid token validation")
    session2 = "user_session_456"
    token2 = csrf.generate_csrf_token(session2)
    result2 = csrf.validate_csrf_token(session2, "invalid_token_xyz")
    print(f"Validation Result: {result2}")
    print("Expected: False\\n")
    
    # Test Case 3: Token reuse prevention
    print("Test Case 3: Token reuse prevention")
    session3 = "user_session_789"
    token3 = csrf.generate_csrf_token(session3)
    csrf.validate_csrf_token(session3, token3)
    result3 = csrf.validate_csrf_token(session3, token3)
    print(f"Second Validation Result: {result3}")
    print("Expected: False (token already used)\\n")
    
    # Test Case 4: Session mismatch
    print("Test Case 4: Session mismatch")
    session4a = "user_session_aaa"
    session4b = "user_session_bbb"
    token4 = csrf.generate_csrf_token(session4a)
    result4 = csrf.validate_csrf_token(session4b, token4)
    print(f"Validation Result: {result4}")
    print("Expected: False\\n")
    
    # Test Case 5: Null/empty input validation
    print("Test Case 5: Null/empty input validation")
    result5a = csrf.validate_csrf_token(None, "some_token")
    result5b = csrf.validate_csrf_token("session", None)
    result5c = csrf.validate_csrf_token("", "token")
    print(f"None session validation: {result5a}")
    print(f"None token validation: {result5b}")
    print(f"Empty session validation: {result5c}")
    print("Expected: False, False, False\\n")


if __name__ == "__main__":
    main()
