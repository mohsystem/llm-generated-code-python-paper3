
import uuid
from datetime import datetime
from typing import Dict, List, Optional

class Task123:
    class Session:
        def __init__(self, user_id: str, session_id: str, login_time: datetime):
            self.user_id = user_id
            self.session_id = session_id
            self.login_time = login_time
            self.last_activity_time = login_time
            self.active = True
    
    def __init__(self):
        self.sessions: Dict[str, Task123.Session] = {}
        self.formatter = "%Y-%m-%d %H:%M:%S"
    
    def create_session(self, user_id: str) -> str:
        session_id = str(uuid.uuid4())
        session = self.Session(user_id, session_id, datetime.now())
        self.sessions[session_id] = session
        return session_id
    
    def is_session_active(self, session_id: str) -> bool:
        session = self.sessions.get(session_id)
        return session is not None and session.active
    
    def update_activity(self, session_id: str) -> None:
        session = self.sessions.get(session_id)
        if session and session.active:
            session.last_activity_time = datetime.now()
    
    def end_session(self, session_id: str) -> None:
        session = self.sessions.get(session_id)
        if session:
            session.active = False
    
    def get_session_info(self, session_id: str) -> str:
        session = self.sessions.get(session_id)
        if not session:
            return "Session not found"
        return f"User: {session.user_id}, Active: {session.active}, Login: {session.login_time.strftime(self.formatter)}, Last Activity: {session.last_activity_time.strftime(self.formatter)}"
    
    def get_active_sessions(self, user_id: str) -> List[str]:
        result = []
        for session in self.sessions.values():
            if session.user_id == user_id and session.active:
                result.append(session.session_id)
        return result
    
    def get_active_session_count(self) -> int:
        count = 0
        for session in self.sessions.values():
            if session.active:
                count += 1
        return count


if __name__ == "__main__":
    import time
    
    manager = Task123()
    
    print("Test Case 1: Create sessions for users")
    session1 = manager.create_session("user1")
    session2 = manager.create_session("user2")
    session3 = manager.create_session("user1")
    print(f"Created sessions: {session1[:8]}..., {session2[:8]}..., {session3[:8]}...")
    print(f"Active session count: {manager.get_active_session_count()}")
    print()
    
    print("Test Case 2: Check session status")
    print(f"Session 1 active: {manager.is_session_active(session1)}")
    print(f"Invalid session active: {manager.is_session_active('invalid-id')}")
    print()
    
    print("Test Case 3: Update activity and get session info")
    time.sleep(1)
    manager.update_activity(session1)
    print(manager.get_session_info(session1))
    print()
    
    print("Test Case 4: Get active sessions for user")
    user1_sessions = manager.get_active_sessions("user1")
    print(f"User1 has {len(user1_sessions)} active sessions")
    print()
    
    print("Test Case 5: End session and verify")
    manager.end_session(session1)
    print(f"Session 1 active after ending: {manager.is_session_active(session1)}")
    print(f"Active session count: {manager.get_active_session_count()}")
    user1_sessions = manager.get_active_sessions("user1")
    print(f"User1 now has {len(user1_sessions)} active sessions")
