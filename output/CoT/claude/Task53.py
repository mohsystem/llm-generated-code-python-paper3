
import secrets
import time
from typing import Dict, Set, Optional

class Task53:
    SESSION_TIMEOUT_SECONDS = 1800  # 30 minutes
    ABSOLUTE_TIMEOUT_SECONDS = 7200  # 2 hours
    SESSION_ID_LENGTH = 32
    
    def __init__(self):
        self.sessions: Dict[str, 'Task53.Session'] = {}
        self.user_sessions: Dict[str, Set[str]] = {}
    
    class Session:
        def __init__(self, session_id: str, user_id: str):
            self.session_id = session_id
            self.user_id = user_id
            self.created_at = time.time()
            self.last_accessed_at = self.created_at
            self.attributes: Dict[str, str] = {}
        
        def is_expired(self) -> bool:
            now = time.time()
            idle_expired = (now - self.last_accessed_at) > Task53.SESSION_TIMEOUT_SECONDS
            absolute_expired = (now - self.created_at) > Task53.ABSOLUTE_TIMEOUT_SECONDS
            return idle_expired or absolute_expired
        
        def update_access(self):
            self.last_accessed_at = time.time()
    
    def _generate_session_id(self) -> str:
        return secrets.token_hex(self.SESSION_ID_LENGTH)
    
    def create_session(self, user_id: str) -> Optional[str]:
        if not user_id or not user_id.strip():
            return None
        
        session_id = self._generate_session_id()
        session = self.Session(session_id, user_id)
        self.sessions[session_id] = session
        
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = set()
        self.user_sessions[user_id].add(session_id)
        
        return session_id
    
    def validate_session(self, session_id: str) -> bool:
        if not session_id:
            return False
        
        session = self.sessions.get(session_id)
        if not session:
            return False
        
        if session.is_expired():
            self.invalidate_session(session_id)
            return False
        
        session.update_access()
        return True
    
    def invalidate_session(self, session_id: str):
        session = self.sessions.pop(session_id, None)
        if session:
            user_session_set = self.user_sessions.get(session.user_id)
            if user_session_set:
                user_session_set.discard(session_id)
                if not user_session_set:
                    del self.user_sessions[session.user_id]
    
    def invalidate_all_user_sessions(self, user_id: str):
        user_session_set = self.user_sessions.get(user_id)
        if user_session_set:
            for session_id in list(user_session_set):
                self.sessions.pop(session_id, None)
            del self.user_sessions[user_id]
    
    def get_active_session_count(self, user_id: str) -> int:
        user_session_set = self.user_sessions.get(user_id)
        if not user_session_set:
            return 0
        
        valid_sessions = set()
        for session_id in list(user_session_set):
            if self.validate_session(session_id):
                valid_sessions.add(session_id)
        return len(valid_sessions)
    
    def cleanup_expired_sessions(self):
        for session_id in list(self.sessions.keys()):
            session = self.sessions.get(session_id)
            if session and session.is_expired():
                self.invalidate_session(session_id)


def main():
    session_manager = Task53()
    
    # Test Case 1: Create and validate session
    print("Test Case 1: Create and validate session")
    session1 = session_manager.create_session("user1")
    print(f"Session created: {session1 is not None}")
    print(f"Session valid: {session_manager.validate_session(session1)}")
    print()
    
    # Test Case 2: Multiple sessions for same user
    print("Test Case 2: Multiple sessions for same user")
    session2 = session_manager.create_session("user1")
    session3 = session_manager.create_session("user1")
    print(f"Active sessions for user1: {session_manager.get_active_session_count('user1')}")
    print()
    
    # Test Case 3: Invalidate specific session
    print("Test Case 3: Invalidate specific session")
    session_manager.invalidate_session(session2)
    print(f"Session2 valid after invalidation: {session_manager.validate_session(session2)}")
    print(f"Active sessions for user1: {session_manager.get_active_session_count('user1')}")
    print()
    
    # Test Case 4: Invalidate all user sessions
    print("Test Case 4: Invalidate all user sessions")
    session_manager.invalidate_all_user_sessions("user1")
    print(f"Session1 valid after user invalidation: {session_manager.validate_session(session1)}")
    print(f"Active sessions for user1: {session_manager.get_active_session_count('user1')}")
    print()
    
    # Test Case 5: Invalid session handling
    print("Test Case 5: Invalid session handling")
    print(f"Null session valid: {session_manager.validate_session(None)}")
    print(f"Non-existent session valid: {session_manager.validate_session('invalid123')}")
    null_user_session = session_manager.create_session(None)
    print(f"Session created with null user: {null_user_session is not None}")


if __name__ == "__main__":
    main()
