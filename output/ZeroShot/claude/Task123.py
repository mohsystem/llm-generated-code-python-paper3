
import secrets
import base64
from datetime import datetime, timedelta
from typing import Dict, Optional

class Task123:
    SESSION_TIMEOUT_MINUTES = 30
    TOKEN_LENGTH = 32
    
    def __init__(self):
        self.sessions: Dict[str, dict] = {}
    
    def create_session(self, user_id: str) -> Optional[str]:
        if not user_id or not user_id.strip():
            return None
        
        token_bytes = secrets.token_bytes(self.TOKEN_LENGTH)
        token = base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')
        
        session = {
            'user_id': user_id,
            'token': token,
            'created_at': datetime.now(),
            'last_accessed_at': datetime.now()
        }
        
        self.sessions[token] = session
        return token
    
    def _is_expired(self, session: dict) -> bool:
        time_diff = datetime.now() - session['last_accessed_at']
        return time_diff.total_seconds() / 60 > self.SESSION_TIMEOUT_MINUTES
    
    def validate_session(self, token: str) -> bool:
        if not token or not token.strip():
            return False
        
        session = self.sessions.get(token)
        if session is None:
            return False
        
        if self._is_expired(session):
            del self.sessions[token]
            return False
        
        session['last_accessed_at'] = datetime.now()
        return True
    
    def get_session_user(self, token: str) -> Optional[str]:
        if not self.validate_session(token):
            return None
        
        session = self.sessions.get(token)
        return session['user_id'] if session else None
    
    def destroy_session(self, token: str) -> bool:
        if not token or not token.strip():
            return False
        
        return self.sessions.pop(token, None) is not None
    
    def cleanup_expired_sessions(self):
        expired_tokens = [
            token for token, session in self.sessions.items()
            if self._is_expired(session)
        ]
        for token in expired_tokens:
            del self.sessions[token]


if __name__ == "__main__":
    session_manager = Task123()
    
    # Test Case 1: Create a session for a user
    print("Test Case 1: Create Session")
    token1 = session_manager.create_session("user123")
    print(f"Token created: {'Yes' if token1 else 'No'}")
    print()
    
    # Test Case 2: Validate an existing session
    print("Test Case 2: Validate Session")
    is_valid = session_manager.validate_session(token1)
    print(f"Session valid: {is_valid}")
    print()
    
    # Test Case 3: Get user from session
    print("Test Case 3: Get Session User")
    user_id = session_manager.get_session_user(token1)
    print(f"User ID: {user_id}")
    print()
    
    # Test Case 4: Destroy a session
    print("Test Case 4: Destroy Session")
    destroyed = session_manager.destroy_session(token1)
    print(f"Session destroyed: {destroyed}")
    valid_after_destroy = session_manager.validate_session(token1)
    print(f"Session valid after destroy: {valid_after_destroy}")
    print()
    
    # Test Case 5: Invalid session token
    print("Test Case 5: Invalid Session Token")
    invalid_token = session_manager.validate_session("invalid_token_xyz")
    print(f"Invalid token validation: {invalid_token}")
    user_from_invalid = session_manager.get_session_user("invalid_token_xyz")
    print(f"User from invalid token: {user_from_invalid}")
