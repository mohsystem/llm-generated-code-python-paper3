import secrets
import time
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Dict, Optional, NamedTuple

class SessionData(NamedTuple):
    user_id: str
    expiration: datetime

class SessionManager:
    _SESSION_ID_BYTES = 32
    _SESSION_TIMEOUT = timedelta(minutes=30)

    def __init__(self):
        self._sessions: Dict[str, SessionData] = {}
        self._lock = Lock()

    def create_session(self, user_id: str) -> str:
        """Creates a new session for a given user."""
        if not user_id:
            raise ValueError("User ID cannot be empty.")
        
        session_id = secrets.token_hex(self._SESSION_ID_BYTES)
        expiration = datetime.now(timezone.utc) + self._SESSION_TIMEOUT
        
        with self._lock:
            self._sessions[session_id] = SessionData(user_id, expiration)
            
        return session_id

    def get_session_user(self, session_id: str) -> Optional[str]:
        """Validates a session ID and returns the associated user ID if valid."""
        if not session_id:
            return None
        
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            
            if session.expiration < datetime.now(timezone.utc):
                # Lazily remove expired session
                del self._sessions[session_id]
                return None
            
            return session.user_id

    def invalidate_session(self, session_id: str) -> None:
        """Removes a session from the store."""
        if not session_id:
            return
            
        with self._lock:
            # Use pop with a default to avoid a KeyError if it doesn't exist
            self._sessions.pop(session_id, None)

def main():
    """Main function with test cases."""
    session_manager = SessionManager()

    print("--- Test Case 1: Create and validate a session ---")
    user_id_1 = "user-123"
    session_id_1 = session_manager.create_session(user_id_1)
    print(f"Created session for {user_id_1}")
    retrieved_user_1 = session_manager.get_session_user(session_id_1)
    print(f"Validated session, user is: {retrieved_user_1}")
    assert user_id_1 == retrieved_user_1
    print("Test Case 1 Passed: True\n")

    print("--- Test Case 2: Invalidate a session ---")
    session_manager.invalidate_session(session_id_1)
    retrieved_user_2 = session_manager.get_session_user(session_id_1)
    print(f"After invalidation, user is: {retrieved_user_2 or 'Not Found'}")
    assert retrieved_user_2 is None
    print("Test Case 2 Passed: True\n")
    
    print("--- Test Case 3: Validate a non-existent session ---")
    retrieved_user_3 = session_manager.get_session_user("non-existent-session-id")
    print(f"Validating non-existent session, user is: {retrieved_user_3 or 'Not Found'}")
    assert retrieved_user_3 is None
    print("Test Case 3 Passed: True\n")

    print("--- Test Case 4: Session expiration ---")
    # A manager with a very short session timeout for testing
    short_lived_manager = SessionManager()
    short_lived_manager._SESSION_TIMEOUT = timedelta(milliseconds=100)
    user_id_4 = "user-456"
    session_id_4 = short_lived_manager.create_session(user_id_4)
    print(f"Created short-lived session for {user_id_4}")
    print("Waiting for session to expire...")
    time.sleep(0.15)
    retrieved_user_4 = short_lived_manager.get_session_user(session_id_4)
    print(f"After expiration, user is: {retrieved_user_4 or 'Not Found'}")
    assert retrieved_user_4 is None
    print("Test Case 4 Passed: True\n")
    
    print("--- Test Case 5: Handle null/empty inputs ---")
    test_5_passed = True
    try:
        session_manager.create_session("")
        test_5_passed = False # Should have raised
    except ValueError:
        print("Caught expected exception for create_session('')")
    
    retrieved_user_5 = session_manager.get_session_user("")
    print(f"get_session_user('') returned: {retrieved_user_5 is None}")
    if retrieved_user_5 is not None:
        test_5_passed = False
    print(f"Test Case 5 Passed: {test_5_passed}\n")

if __name__ == "__main__":
    main()