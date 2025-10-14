import os
import base64
import time
import secrets
from threading import Lock

class SessionManager:
    ABSOLUTE_TIMEOUT_SECONDS = 5  # e.g., 30 minutes
    IDLE_TIMEOUT_SECONDS = 2    # e.g., 5 minutes

    def __init__(self):
        # The session store maps session_id to a dictionary containing session data.
        # In a real multi-threaded web app, access to this dictionary must be synchronized.
        self._session_store = {}
        self._lock = Lock()

    def create_session(self, user_id):
        """
        Creates a new session for a given user.
        :param user_id: The ID of the user.
        :return: A cryptographically secure session ID.
        """
        session_id = secrets.token_urlsafe(32)
        current_time = time.time()
        session_data = {
            "user_id": user_id,
            "creation_time": current_time,
            "last_accessed_time": current_time,
        }
        with self._lock:
            self._session_store[session_id] = session_data
        return session_id

    def get_session(self, session_id):
        """
        Retrieves and validates a session.
        :param session_id: The session ID to validate.
        :return: The session data dictionary if valid, None otherwise.
        """
        if not session_id:
            return None
            
        with self._lock:
            session_data = self._session_store.get(session_id)
            if not session_data:
                return None  # Session does not exist

            current_time = time.time()
            
            # Check for absolute timeout
            if current_time - session_data["creation_time"] > self.ABSOLUTE_TIMEOUT_SECONDS:
                self.invalidate_session(session_id)
                return None  # Session expired
                
            # Check for idle timeout
            if current_time - session_data["last_accessed_time"] > self.IDLE_TIMEOUT_SECONDS:
                self.invalidate_session(session_id)
                return None  # Session expired due to inactivity
                
            # If valid, update the last accessed time
            session_data["last_accessed_time"] = current_time
            return session_data

    def invalidate_session(self, session_id):
        """
        Invalidates (terminates) a session.
        :param session_id: The session ID to invalidate.
        """
        with self._lock:
            if session_id in self._session_store:
                del self._session_store[session_id]

def main():
    manager = SessionManager()
    print("Running Python Session Manager Test Cases...")
    print(f"Absolute Timeout: {manager.ABSOLUTE_TIMEOUT_SECONDS}s, Idle Timeout: {manager.IDLE_TIMEOUT_SECONDS}s\n")
    
    # Test Case 1: Create and validate a new session
    print("--- Test Case 1: Create and Validate Session ---")
    session_id1 = manager.create_session("user123")
    print(f"Created session for user123: {session_id1}")
    s1 = manager.get_session(session_id1)
    print(f"Session valid? {'Yes, for user ' + s1['user_id'] if s1 else 'No'}")
    print()

    # Test Case 2: Invalidate a session
    print("--- Test Case 2: Invalidate Session ---")
    manager.invalidate_session(session_id1)
    print("Session invalidated.")
    s1 = manager.get_session(session_id1)
    print(f"Session valid after invalidation? {s1 is not None}")
    print()

    # Test Case 3: Idle timeout
    print("--- Test Case 3: Idle Timeout ---")
    session_id2 = manager.create_session("user456")
    print(f"Created session for user456: {session_id2}")
    print(f"Waiting for {manager.IDLE_TIMEOUT_SECONDS + 1} seconds to trigger idle timeout...")
    time.sleep(manager.IDLE_TIMEOUT_SECONDS + 1)
    s2 = manager.get_session(session_id2)
    print(f"Session valid after idle period? {s2 is not None}")
    print()

    # Test Case 4: Absolute timeout
    print("--- Test Case 4: Absolute Timeout ---")
    session_id3 = manager.create_session("user789")
    print(f"Created session for user789: {session_id3}")
    print("Accessing session every second to prevent idle timeout...")
    for i in range(manager.ABSOLUTE_TIMEOUT_SECONDS - 1):
        time.sleep(1)
        manager.get_session(session_id3)  # Keep it active
        print(f"Accessed at second {i+1}")
    print("Waiting for absolute timeout...")
    time.sleep(2)
    s3 = manager.get_session(session_id3)
    print(f"Session valid after absolute timeout period? {s3 is not None}")
    print()

    # Test Case 5: Prevent idle timeout by activity
    print("--- Test Case 5: Prevent Idle Timeout ---")
    session_id4 = manager.create_session("userABC")
    print(f"Created session for userABC: {session_id4}")
    time.sleep(manager.IDLE_TIMEOUT_SECONDS - 1)
    print("Accessing session just before idle timeout...")
    s4_active = manager.get_session(session_id4)
    print(f"Session is still active? {s4_active is not None}")
    
    time.sleep(manager.IDLE_TIMEOUT_SECONDS - 1)
    s4_active = manager.get_session(session_id4)
    print(f"Accessing again. Session still active? {s4_active is not None}")
    print()

if __name__ == "__main__":
    main()