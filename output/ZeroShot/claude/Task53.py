
import secrets
import time
from typing import Dict, Optional, Any
from threading import Lock

class Task53:
    SESSION_TIMEOUT_SECONDS = 1800  # 30 minutes
    TOKEN_LENGTH = 32
    
    class Session:
        def __init__(self, session_id: str, user_id: str):
            self.session_id = session_id
            self.user_id = user_id
            self.created_at = time.time()
            self.last_accessed_at = self.created_at
            self.attributes: Dict[str, Any] = {}
        
        def is_expired(self, timeout_seconds: int) -> bool:
            current_time = time.time()
            return (current_time - self.last_accessed_at) > timeout_seconds
        
        def update_last_accessed(self):
            self.last_accessed_at = time.time()
    
    def __init__(self):
        self.sessions: Dict[str, Task53.Session] = {}
        self.lock = Lock()
    
    def create_session(self, user_id: str) -> Optional[str]:
        if not user_id or not user_id.strip():
            return None
        
        session_id = self._generate_secure_token()
        session = Task53.Session(session_id, user_id)
        
        with self.lock:
            self.sessions[session_id] = session
        
        return session_id
    
    def validate_session(self, session_id: str) -> bool:
        if not session_id:
            return False
        
        with self.lock:
            session = self.sessions.get(session_id)
            
            if not session:
                return False
            
            if session.is_expired(self.SESSION_TIMEOUT_SECONDS):
                del self.sessions[session_id]
                return False
            
            session.update_last_accessed()
            return True
    
    def get_user_id(self, session_id: str) -> Optional[str]:
        if not self.validate_session(session_id):
            return None
        
        with self.lock:
            session = self.sessions.get(session_id)
            return session.user_id if session else None
    
    def invalidate_session(self, session_id: str) -> bool:
        if not session_id:
            return False
        
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                return True
            return False
    
    def set_attribute(self, session_id: str, key: str, value: Any):
        if self.validate_session(session_id) and key:
            with self.lock:
                session = self.sessions.get(session_id)
                if session:
                    session.attributes[key] = value
    
    def get_attribute(self, session_id: str, key: str) -> Optional[Any]:
        if self.validate_session(session_id) and key:
            with self.lock:
                session = self.sessions.get(session_id)
                if session:
                    return session.attributes.get(key)
        return None
    
    def cleanup_expired_sessions(self):
        with self.lock:
            expired_sessions = [
                session_id for session_id, session in self.sessions.items()
                if session.is_expired(self.SESSION_TIMEOUT_SECONDS)
            ]
            
            for session_id in expired_sessions:
                del self.sessions[session_id]
    
    def _generate_secure_token(self) -> str:
        return secrets.token_hex(self.TOKEN_LENGTH)


if __name__ == "__main__":
    session_manager = Task53()
    
    # Test Case 1: Create a session
    print("Test Case 1: Create Session")
    session1 = session_manager.create_session("user123")
    print(f"Session created: {session1 is not None}")
    print(f"Session ID length: {len(session1)}")
    
    # Test Case 2: Validate session
    print("\\nTest Case 2: Validate Session")
    is_valid = session_manager.validate_session(session1)
    print(f"Session valid: {is_valid}")
    user_id = session_manager.get_user_id(session1)
    print(f"User ID: {user_id}")
    
    # Test Case 3: Set and get attributes
    print("\\nTest Case 3: Session Attributes")
    session_manager.set_attribute(session1, "username", "JohnDoe")
    session_manager.set_attribute(session1, "role", "admin")
    username = session_manager.get_attribute(session1, "username")
    role = session_manager.get_attribute(session1, "role")
    print(f"Username: {username}")
    print(f"Role: {role}")
    
    # Test Case 4: Invalidate session
    print("\\nTest Case 4: Invalidate Session")
    invalidated = session_manager.invalidate_session(session1)
    print(f"Session invalidated: {invalidated}")
    still_valid = session_manager.validate_session(session1)
    print(f"Session still valid: {still_valid}")
    
    # Test Case 5: Multiple sessions and cleanup
    print("\\nTest Case 5: Multiple Sessions")
    session2 = session_manager.create_session("user456")
    session3 = session_manager.create_session("user789")
    print(f"Session 2 created: {session2 is not None}")
    print(f"Session 3 created: {session3 is not None}")
    session_manager.cleanup_expired_sessions()
    print("Cleanup completed")
    print(f"Session 2 valid: {session_manager.validate_session(session2)}")
