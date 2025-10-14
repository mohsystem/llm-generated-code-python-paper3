
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import hashlib
import base64

class Task43:
    SESSION_TIMEOUT_SECONDS = 1800  # 30 minutes
    SESSION_ID_LENGTH = 32
    sessions: Dict[str, 'Session'] = {}
    
    class Session:
        def __init__(self, session_id: str, user_id: str):
            self.session_id = session_id
            self.user_id = user_id
            self.created_at = datetime.now()
            self.last_accessed_at = datetime.now()
            self.attributes: Dict[str, Any] = {}
        
        def is_expired(self) -> bool:
            elapsed = (datetime.now() - self.last_accessed_at).total_seconds()
            return elapsed > Task43.SESSION_TIMEOUT_SECONDS
        
        def update_last_accessed(self):
            self.last_accessed_at = datetime.now()
    
    @staticmethod
    def create_session(user_id: str) -> Optional[str]:
        if not user_id or not user_id.strip():
            return None
        
        Task43.clean_expired_sessions()
        
        session_id = base64.urlsafe_b64encode(
            secrets.token_bytes(Task43.SESSION_ID_LENGTH)
        ).decode('utf-8').rstrip('=')
        
        session = Task43.Session(session_id, user_id)
        Task43.sessions[session_id] = session
        
        return session_id
    
    @staticmethod
    def validate_session(session_id: str) -> bool:
        if not session_id or not session_id.strip():
            return False
        
        session = Task43.sessions.get(session_id)
        if not session:
            return False
        
        if session.is_expired():
            Task43.terminate_session(session_id)
            return False
        
        session.update_last_accessed()
        return True
    
    @staticmethod
    def get_session_user_id(session_id: str) -> Optional[str]:
        if not Task43.validate_session(session_id):
            return None
        return Task43.sessions[session_id].user_id
    
    @staticmethod
    def terminate_session(session_id: str) -> bool:
        if not session_id:
            return False
        return Task43.sessions.pop(session_id, None) is not None
    
    @staticmethod
    def clean_expired_sessions():
        expired = [sid for sid, session in Task43.sessions.items() 
                   if session.is_expired()]
        for sid in expired:
            del Task43.sessions[sid]
    
    @staticmethod
    def set_session_attribute(session_id: str, key: str, value: Any) -> bool:
        if not Task43.validate_session(session_id) or not key:
            return False
        Task43.sessions[session_id].attributes[key] = value
        return True
    
    @staticmethod
    def get_session_attribute(session_id: str, key: str) -> Optional[Any]:
        if not Task43.validate_session(session_id) or not key:
            return None
        return Task43.sessions[session_id].attributes.get(key)
    
    @staticmethod
    def get_active_session_count() -> int:
        Task43.clean_expired_sessions()
        return len(Task43.sessions)


def main():
    print("=== Secure Session Management Test Cases ===\\n")
    
    # Test Case 1: Create and validate session
    print("Test Case 1: Create and Validate Session")
    session1 = Task43.create_session("user123")
    print(f"Session created: {session1 is not None}")
    print(f"Session valid: {Task43.validate_session(session1)}")
    print(f"User ID: {Task43.get_session_user_id(session1)}")
    print()
    
    # Test Case 2: Session attributes
    print("Test Case 2: Session Attributes")
    session2 = Task43.create_session("user456")
    Task43.set_session_attribute(session2, "role", "admin")
    Task43.set_session_attribute(session2, "loginTime", str(datetime.now()))
    print(f"Role attribute: {Task43.get_session_attribute(session2, 'role')}")
    print(f"Login time set: {Task43.get_session_attribute(session2, 'loginTime') is not None}")
    print()
    
    # Test Case 3: Invalid session handling
    print("Test Case 3: Invalid Session Handling")
    print(f"Null session valid: {Task43.validate_session(None)}")
    print(f"Empty session valid: {Task43.validate_session('')}")
    print(f"Fake session valid: {Task43.validate_session('fake-session-id')}")
    print()
    
    # Test Case 4: Session termination
    print("Test Case 4: Session Termination")
    session3 = Task43.create_session("user789")
    print(f"Session created: {Task43.validate_session(session3)}")
    terminated = Task43.terminate_session(session3)
    print(f"Session terminated: {terminated}")
    print(f"Session still valid: {Task43.validate_session(session3)}")
    print()
    
    # Test Case 5: Active session count
    print("Test Case 5: Active Session Count")
    Task43.create_session("user001")
    Task43.create_session("user002")
    Task43.create_session("user003")
    count = Task43.get_active_session_count()
    print(f"Active sessions: {count}")
    Task43.clean_expired_sessions()
    print(f"After cleanup: {Task43.get_active_session_count()}")
    print()


if __name__ == "__main__":
    main()
