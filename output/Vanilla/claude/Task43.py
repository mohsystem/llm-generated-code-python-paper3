
import secrets
import base64
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import threading

class Task43:
    SESSION_TIMEOUT_MINUTES = 30
    TOKEN_LENGTH = 32
    
    class Session:
        def __init__(self, session_id: str, user_id: str):
            self.session_id = session_id
            self.user_id = user_id
            self.created_at = datetime.now()
            self.last_accessed_at = datetime.now()
            self.attributes: Dict[str, Any] = {}
            self._lock = threading.Lock()
        
        def update_last_accessed(self):
            with self._lock:
                self.last_accessed_at = datetime.now()
        
        def is_expired(self) -> bool:
            timeout = timedelta(minutes=Task43.SESSION_TIMEOUT_MINUTES)
            return datetime.now() > self.last_accessed_at + timeout
        
        def set_attribute(self, key: str, value: Any):
            with self._lock:
                self.attributes[key] = value
        
        def get_attribute(self, key: str) -> Optional[Any]:
            return self.attributes.get(key)
        
        def __str__(self):
            return (f"Session(id='{self.session_id}', user_id='{self.user_id}', "
                   f"created={self.created_at}, last_accessed={self.last_accessed_at}, "
                   f"expired={self.is_expired()})")
    
    class SessionManager:
        def __init__(self):
            self.sessions: Dict[str, Task43.Session] = {}
            self._lock = threading.Lock()
        
        def create_session(self, user_id: str) -> str:
            session_id = self._generate_session_id()
            session = Task43.Session(session_id, user_id)
            with self._lock:
                self.sessions[session_id] = session
                self._cleanup_expired_sessions()
            return session_id
        
        def get_session(self, session_id: str) -> Optional['Task43.Session']:
            with self._lock:
                session = self.sessions.get(session_id)
                if session:
                    if session.is_expired():
                        self.terminate_session(session_id)
                        return None
                    session.update_last_accessed()
                return session
        
        def validate_session(self, session_id: str) -> bool:
            return self.get_session(session_id) is not None
        
        def terminate_session(self, session_id: str):
            with self._lock:
                self.sessions.pop(session_id, None)
        
        def terminate_user_sessions(self, user_id: str):
            with self._lock:
                to_remove = [sid for sid, session in self.sessions.items() 
                           if session.user_id == user_id]
                for sid in to_remove:
                    del self.sessions[sid]
        
        def get_active_session_count(self) -> int:
            with self._lock:
                self._cleanup_expired_sessions()
                return len(self.sessions)
        
        def _generate_session_id(self) -> str:
            random_bytes = secrets.token_bytes(Task43.TOKEN_LENGTH)
            return base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        
        def _cleanup_expired_sessions(self):
            expired = [sid for sid, session in self.sessions.items() if session.is_expired()]
            for sid in expired:
                del self.sessions[sid]


def main():
    manager = Task43.SessionManager()
    
    print("=== Test Case 1: Create Session ===")
    session_id1 = manager.create_session("user123")
    print(f"Created session: {session_id1}")
    print(f"Session valid: {manager.validate_session(session_id1)}")
    
    print("\\n=== Test Case 2: Get Session and Update Access Time ===")
    session1 = manager.get_session(session_id1)
    print(session1)
    session1.set_attribute("username", "JohnDoe")
    print(f"Username attribute: {session1.get_attribute('username')}")
    
    print("\\n=== Test Case 3: Multiple Sessions ===")
    session_id2 = manager.create_session("user456")
    session_id3 = manager.create_session("user789")
    print(f"Active sessions: {manager.get_active_session_count()}")
    
    print("\\n=== Test Case 4: Terminate Specific Session ===")
    manager.terminate_session(session_id2)
    print(f"Session 2 valid after termination: {manager.validate_session(session_id2)}")
    print(f"Active sessions: {manager.get_active_session_count()}")
    
    print("\\n=== Test Case 5: Terminate All User Sessions ===")
    session_id4 = manager.create_session("user123")
    print("Created another session for user123")
    print(f"Active sessions before cleanup: {manager.get_active_session_count()}")
    manager.terminate_user_sessions("user123")
    print(f"Active sessions after user123 cleanup: {manager.get_active_session_count()}")
    print(f"Session 1 valid: {manager.validate_session(session_id1)}")
    print(f"Session 4 valid: {manager.validate_session(session_id4)}")


if __name__ == "__main__":
    main()
