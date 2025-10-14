
import secrets
import base64
import time
from typing import Dict, Optional

class Task135:
    TOKEN_LENGTH = 32
    TOKEN_EXPIRY_MS = 30 * 60 * 1000  # 30 minutes in milliseconds
    
    class TokenData:
        def __init__(self, token: str, created_at: int, session_id: str):
            self.token = token
            self.created_at = created_at
            self.session_id = session_id
        
        def is_expired(self) -> bool:
            return int(time.time() * 1000) - self.created_at > Task135.TOKEN_EXPIRY_MS
    
    def __init__(self):
        self.token_store: Dict[str, Task135.TokenData] = {}
    
    def generate_token(self, session_id: str) -> str:
        random_bytes = secrets.token_bytes(self.TOKEN_LENGTH)
        token = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        
        token_data = self.TokenData(token, int(time.time() * 1000), session_id)
        self.token_store[session_id] = token_data
        
        return token
    
    def validate_token(self, session_id: Optional[str], token: Optional[str]) -> bool:
        if session_id is None or token is None:
            return False
        
        token_data = self.token_store.get(session_id)
        
        if token_data is None:
            return False
        
        if token_data.is_expired():
            del self.token_store[session_id]
            return False
        
        return token_data.token == token
    
    def invalidate_token(self, session_id: str):
        if session_id in self.token_store:
            del self.token_store[session_id]
    
    def clean_expired_tokens(self):
        expired_sessions = [sid for sid, data in self.token_store.items() if data.is_expired()]
        for sid in expired_sessions:
            del self.token_store[sid]
    
    def get_active_token_count(self) -> int:
        self.clean_expired_tokens()
        return len(self.token_store)


def main():
    csrf_protection = Task135()
    
    # Test Case 1: Generate and validate token
    print("Test Case 1: Generate and validate token")
    session1 = "session_123"
    token1 = csrf_protection.generate_token(session1)
    print(f"Generated token: {token1}")
    print(f"Token valid: {csrf_protection.validate_token(session1, token1)}")
    print()
    
    # Test Case 2: Invalid token validation
    print("Test Case 2: Invalid token validation")
    session2 = "session_456"
    token2 = csrf_protection.generate_token(session2)
    print(f"Valid token check: {csrf_protection.validate_token(session2, token2)}")
    print(f"Invalid token check: {csrf_protection.validate_token(session2, 'invalid_token')}")
    print()
    
    # Test Case 3: Token invalidation
    print("Test Case 3: Token invalidation")
    session3 = "session_789"
    token3 = csrf_protection.generate_token(session3)
    print(f"Before invalidation: {csrf_protection.validate_token(session3, token3)}")
    csrf_protection.invalidate_token(session3)
    print(f"After invalidation: {csrf_protection.validate_token(session3, token3)}")
    print()
    
    # Test Case 4: Multiple sessions
    print("Test Case 4: Multiple sessions")
    session_a = "session_A"
    session_b = "session_B"
    token_a = csrf_protection.generate_token(session_a)
    token_b = csrf_protection.generate_token(session_b)
    print(f"Session A valid: {csrf_protection.validate_token(session_a, token_a)}")
    print(f"Session B valid: {csrf_protection.validate_token(session_b, token_b)}")
    print(f"Cross-session invalid: {csrf_protection.validate_token(session_a, token_b)}")
    print(f"Active tokens: {csrf_protection.get_active_token_count()}")
    print()
    
    # Test Case 5: Null handling
    print("Test Case 5: Null handling")
    print(f"Null session: {csrf_protection.validate_token(None, 'token')}")
    print(f"Null token: {csrf_protection.validate_token('session', None)}")
    print(f"Both null: {csrf_protection.validate_token(None, None)}")


if __name__ == "__main__":
    main()
