
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

class Task53:
    class Session:
        def __init__(self, session_id: str, user_id: str):
            self.session_id = session_id
            self.user_id = user_id
            self.created_at = datetime.now()
            self.last_accessed_at = datetime.now()
            self.data: Dict[str, Any] = {}
        
        def update_last_accessed(self):
            self.last_accessed_at = datetime.now()
        
        def is_expired(self, timeout_minutes: int) -> bool:
            duration = datetime.now() - self.last_accessed_at
            return duration.total_seconds() / 60 >= timeout_minutes
    
    def __init__(self, session_timeout: int):
        self.sessions: Dict[str, Task53.Session] = {}
        self.session_timeout = session_timeout
    
    def create_session(self, user_id: str) -> str:
        session_id = str(uuid.uuid4())
        session = Task53.Session(session_id, user_id)
        self.sessions[session_id] = session
        return session_id
    
    def validate_session(self, session_id: str) -> bool:
        session = self.sessions.get(session_id)
        if session is None:
            return False
        if session.is_expired(self.session_timeout):
            del self.sessions[session_id]
            return False
        session.update_last_accessed()
        return True
    
    def destroy_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]
    
    def set_session_data(self, session_id: str, key: str, value: Any):
        session = self.sessions.get(session_id)
        if session is not None and not session.is_expired(self.session_timeout):
            session.data[key] = value
            session.update_last_accessed()
    
    def get_session_data(self, session_id: str, key: str) -> Optional[Any]:
        session = self.sessions.get(session_id)
        if session is not None and not session.is_expired(self.session_timeout):
            session.update_last_accessed()
            return session.data.get(key)
        return None
    
    def get_user_id(self, session_id: str) -> Optional[str]:
        session = self.sessions.get(session_id)
        if session is not None and not session.is_expired(self.session_timeout):
            return session.user_id
        return None
    
    def cleanup_expired_sessions(self):
        expired_sessions = [
            sid for sid, session in self.sessions.items()
            if session.is_expired(self.session_timeout)
        ]
        for session_id in expired_sessions:
            del self.sessions[session_id]
    
    def get_active_session_count(self) -> int:
        self.cleanup_expired_sessions()
        return len(self.sessions)


if __name__ == "__main__":
    print("Test Case 1: Create and validate session")
    manager1 = Task53(30)
    session_id1 = manager1.create_session("user123")
    print(f"Session created: {session_id1}")
    print(f"Session valid: {manager1.validate_session(session_id1)}")
    print(f"User ID: {manager1.get_user_id(session_id1)}")
    print()
    
    print("Test Case 2: Store and retrieve session data")
    manager2 = Task53(30)
    session_id2 = manager2.create_session("user456")
    manager2.set_session_data(session_id2, "username", "JohnDoe")
    manager2.set_session_data(session_id2, "email", "john@example.com")
    print(f"Username: {manager2.get_session_data(session_id2, 'username')}")
    print(f"Email: {manager2.get_session_data(session_id2, 'email')}")
    print()
    
    print("Test Case 3: Destroy session")
    manager3 = Task53(30)
    session_id3 = manager3.create_session("user789")
    print(f"Before destroy - Valid: {manager3.validate_session(session_id3)}")
    manager3.destroy_session(session_id3)
    print(f"After destroy - Valid: {manager3.validate_session(session_id3)}")
    print()
    
    print("Test Case 4: Multiple sessions")
    manager4 = Task53(30)
    session1 = manager4.create_session("user1")
    session2 = manager4.create_session("user2")
    session3 = manager4.create_session("user3")
    print(f"Active sessions: {manager4.get_active_session_count()}")
    manager4.destroy_session(session2)
    print(f"After destroying one: {manager4.get_active_session_count()}")
    print()
    
    print("Test Case 5: Invalid session operations")
    manager5 = Task53(30)
    print(f"Validate non-existent session: {manager5.validate_session('invalid-id')}")
    print(f"Get data from non-existent session: {manager5.get_session_data('invalid-id', 'key')}")
    valid_session = manager5.create_session("user999")
    manager5.destroy_session(valid_session)
    print(f"Get user from destroyed session: {manager5.get_user_id(valid_session)}")
