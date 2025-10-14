
import secrets
import time
from threading import Lock, Thread
from typing import Dict, Optional

class Task123:
    SESSION_TIMEOUT_SECONDS = 1800  # 30 minutes
    TOKEN_LENGTH = 32
    
    def __init__(self):
        self.sessions: Dict[str, 'Session'] = {}
        self.lock = Lock()
        self.cleanup_thread = Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
    
    class Session:
        def __init__(self, user_id: str):
            if not user_id or not user_id.strip():
                raise ValueError("User ID cannot be null or empty")
            self.user_id = self._sanitize_input(user_id)
            self.created_at = time.time()
            self.last_accessed_at = time.time()
            self.attributes: Dict[str, str] = {}
        
        @staticmethod
        def _sanitize_input(input_str: str) -> str:
            if not input_str:
                return ""
            sanitized = ''.join(c for c in input_str if c.isalnum() or c in '@._-')
            return sanitized[:256]
        
        def is_expired(self, timeout: int) -> bool:
            return time.time() - self.last_accessed_at > timeout
        
        def update_last_accessed(self):
            self.last_accessed_at = time.time()
        
        def set_attribute(self, key: str, value: str):
            if key and value:
                self.attributes[self._sanitize_input(key)] = self._sanitize_input(value)
        
        def get_attribute(self, key: str) -> Optional[str]:
            return self.attributes.get(self._sanitize_input(key)) if key else None
    
    def create_session(self, user_id: str) -> Optional[str]:
        try:
            if not user_id or not user_id.strip():
                return None
            
            session_token = secrets.token_urlsafe(self.TOKEN_LENGTH)
            
            with self.lock:
                session = self.Session(user_id)
                self.sessions[session_token] = session
            
            return session_token
        except Exception:
            return None
    
    def validate_session(self, session_token: str) -> bool:
        try:
            if not session_token or not session_token.strip():
                return False
            
            with self.lock:
                session = self.sessions.get(session_token)
                if not session or session.is_expired(self.SESSION_TIMEOUT_SECONDS):
                    if session:
                        del self.sessions[session_token]
                    return False
                
                session.update_last_accessed()
                return True
        except Exception:
            return False
    
    def get_session_user_id(self, session_token: str) -> Optional[str]:
        try:
            if not self.validate_session(session_token):
                return None
            
            with self.lock:
                session = self.sessions.get(session_token)
                return session.user_id if session else None
        except Exception:
            return None
    
    def invalidate_session(self, session_token: str) -> bool:
        try:
            if not session_token or not session_token.strip():
                return False
            
            with self.lock:
                return self.sessions.pop(session_token, None) is not None
        except Exception:
            return False
    
    def set_session_attribute(self, session_token: str, key: str, value: str) -> bool:
        try:
            if not self.validate_session(session_token):
                return False
            
            with self.lock:
                session = self.sessions.get(session_token)
                if session:
                    session.set_attribute(key, value)
                    return True
                return False
        except Exception:
            return False
    
    def get_session_attribute(self, session_token: str, key: str) -> Optional[str]:
        try:
            if not self.validate_session(session_token):
                return None
            
            with self.lock:
                session = self.sessions.get(session_token)
                return session.get_attribute(key) if session else None
        except Exception:
            return None
    
    def _cleanup_expired_sessions(self):
        with self.lock:
            expired_tokens = [
                token for token, session in self.sessions.items()
                if session.is_expired(self.SESSION_TIMEOUT_SECONDS)
            ]
            for token in expired_tokens:
                del self.sessions[token]
    
    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            self._cleanup_expired_sessions()


def main():
    print("=== User Session Management Tests ===\\n")
    
    manager = Task123()
    
    # Test Case 1: Create valid session
    print("Test 1: Create Session")
    token1 = manager.create_session("user123")
    print(f"Session created: {'Success' if token1 else 'Failed'}")
    print(f"Token length: {len(token1) if token1 else 0}")
    
    # Test Case 2: Validate existing session
    print("\\nTest 2: Validate Session")
    is_valid = manager.validate_session(token1)
    print(f"Session validation: {'Valid' if is_valid else 'Invalid'}")
    
    # Test Case 3: Set and get session attributes
    print("\\nTest 3: Session Attributes")
    manager.set_session_attribute(token1, "email", "user@example.com")
    manager.set_session_attribute(token1, "role", "admin")
    email = manager.get_session_attribute(token1, "email")
    role = manager.get_session_attribute(token1, "role")
    print(f"Email: {email}")
    print(f"Role: {role}")
    
    # Test Case 4: Get user ID from session
    print("\\nTest 4: Get User ID")
    user_id = manager.get_session_user_id(token1)
    print(f"User ID: {user_id}")
    
    # Test Case 5: Invalidate session
    print("\\nTest 5: Invalidate Session")
    invalidated = manager.invalidate_session(token1)
    print(f"Session invalidated: {invalidated}")
    still_valid = manager.validate_session(token1)
    print(f"Session still valid: {still_valid}")


if __name__ == "__main__":
    main()
