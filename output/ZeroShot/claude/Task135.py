
import secrets
import base64
import time
from typing import Dict, Optional

class Task135:
    def __init__(self):
        self.TOKEN_LENGTH = 32
        self.TOKEN_EXPIRY_TIME = 30 * 60  # 30 minutes in seconds
        self.token_store: Dict[str, dict] = {}
    
    def generate_token(self, session_id: str) -> str:
        """Generate a new CSRF token for a session"""
        token_bytes = secrets.token_bytes(self.TOKEN_LENGTH)
        token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
        
        self.token_store[session_id] = {
            'token': token,
            'timestamp': time.time()
        }
        
        return token
    
    def validate_token(self, session_id: str, token: str) -> bool:
        """Validate CSRF token"""
        if not session_id or not token:
            return False
        
        token_data = self.token_store.get(session_id)
        
        if not token_data:
            return False
        
        # Check if token has expired
        if time.time() - token_data['timestamp'] > self.TOKEN_EXPIRY_TIME:
            self.token_store.pop(session_id, None)
            return False
        
        # Constant-time comparison to prevent timing attacks
        return self._constant_time_equals(token_data['token'], token)
    
    def invalidate_token(self, session_id: str) -> None:
        """Invalidate token after use (for single-use tokens)"""
        self.token_store.pop(session_id, None)
    
    def _constant_time_equals(self, a: str, b: str) -> bool:
        """Constant-time string comparison"""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0
    
    def cleanup_expired_tokens(self) -> None:
        """Clean up expired tokens"""
        current_time = time.time()
        expired_sessions = [
            session_id for session_id, data in self.token_store.items()
            if current_time - data['timestamp'] > self.TOKEN_EXPIRY_TIME
        ]
        
        for session_id in expired_sessions:
            self.token_store.pop(session_id, None)


def main():
    csrf_protection = Task135()
    
    print("=== CSRF Protection Test Cases ===\\n")
    
    # Test Case 1: Generate and validate valid token
    print("Test Case 1: Generate and validate valid token")
    session1 = "session123"
    token1 = csrf_protection.generate_token(session1)
    print(f"Generated Token: {token1}")
    print(f"Validation Result: {csrf_protection.validate_token(session1, token1)}")
    print()
    
    # Test Case 2: Validate with wrong token
    print("Test Case 2: Validate with wrong token")
    session2 = "session456"
    token2 = csrf_protection.generate_token(session2)
    wrong_token = "wrongToken123"
    print(f"Generated Token: {token2}")
    print(f"Wrong Token: {wrong_token}")
    print(f"Validation Result: {csrf_protection.validate_token(session2, wrong_token)}")
    print()
    
    # Test Case 3: Validate with non-existent session
    print("Test Case 3: Validate with non-existent session")
    non_existent_session = "nonExistent"
    token3 = "someToken"
    print(f"Validation Result: {csrf_protection.validate_token(non_existent_session, token3)}")
    print()
    
    # Test Case 4: Invalidate token and try to use it
    print("Test Case 4: Invalidate token and try to use it")
    session4 = "session789"
    token4 = csrf_protection.generate_token(session4)
    print(f"Generated Token: {token4}")
    print(f"Validation Before Invalidation: {csrf_protection.validate_token(session4, token4)}")
    csrf_protection.invalidate_token(session4)
    print(f"Validation After Invalidation: {csrf_protection.validate_token(session4, token4)}")
    print()
    
    # Test Case 5: Multiple sessions with different tokens
    print("Test Case 5: Multiple sessions with different tokens")
    session_a = "sessionA"
    session_b = "sessionB"
    token_a = csrf_protection.generate_token(session_a)
    token_b = csrf_protection.generate_token(session_b)
    print(f"Session A Token: {token_a}")
    print(f"Session B Token: {token_b}")
    print(f"Validate A with A's token: {csrf_protection.validate_token(session_a, token_a)}")
    print(f"Validate B with B's token: {csrf_protection.validate_token(session_b, token_b)}")
    print(f"Validate A with B's token: {csrf_protection.validate_token(session_a, token_b)}")
    print(f"Validate B with A's token: {csrf_protection.validate_token(session_b, token_a)}")


if __name__ == "__main__":
    main()
