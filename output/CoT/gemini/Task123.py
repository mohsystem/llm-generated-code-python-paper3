import uuid
import time
import threading

class SessionManager:
    def __init__(self, timeout_seconds=300):
        """
        Initializes the SessionManager.
        :param timeout_seconds: The duration for which a session is valid.
        """
        self._sessions = {}
        self._timeout = timeout_seconds
        # A lock is necessary for thread safety
        self._lock = threading.Lock()

    def create_session(self, username: str) -> str:
        """
        Creates a new session for a user.
        :param username: The username for whom to create the session.
        :return: A unique session ID.
        """
        if not username or not username.strip():
            raise ValueError("Username cannot be null or empty.")
        
        # uuid.uuid4() is recommended for generating secure random IDs
        session_id = str(uuid.uuid4())
        expiry_time = time.time() + self._timeout
        
        with self._lock:
            self._sessions[session_id] = {
                'username': username,
                'expiry_time': expiry_time
            }
        return session_id

    def is_valid_session(self, session_id: str) -> bool:
        """
        Checks if a session ID is valid and not expired.
        :param session_id: The session ID to validate.
        :return: True if the session is valid, False otherwise.
        """
        if not session_id:
            return False
            
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            
            if time.time() > session['expiry_time']:
                # Lazy cleanup of expired sessions
                del self._sessions[session_id]
                return False
                
            return True

    def get_username(self, session_id: str) -> str or None:
        """
        Retrieves the username associated with a valid session.
        :param session_id: The session ID.
        :return: The username, or None if the session is invalid.
        """
        if self.is_valid_session(session_id):
            with self._lock:
                # We need to re-check existence in case it expired between calls
                if session_id in self._sessions:
                    return self._sessions[session_id]['username']
        return None

    def invalidate_session(self, session_id: str):
        """
        Invalidates/removes a session.
        :param session_id: The session ID to invalidate.
        """
        if session_id:
            with self._lock:
                # Use pop with a default to avoid KeyError if it doesn't exist
                self._sessions.pop(session_id, None)

# Main execution block with test cases
def main():
    print("--- Python Session Manager ---")
    # Test Case 1: Create and validate a new session
    print("\n--- Test Case 1: Create and Validate Session ---")
    manager = SessionManager(timeout_seconds=300)
    session_id1 = manager.create_session("userA")
    print(f"Created session for userA: {session_id1}")
    print(f"Is session valid? {manager.is_valid_session(session_id1)}")
    print(f"Username from session: {manager.get_username(session_id1)}")

    # Test Case 2: Invalidate a session
    print("\n--- Test Case 2: Invalidate Session ---")
    manager.invalidate_session(session_id1)
    print("Session for userA invalidated.")
    print(f"Is session valid after invalidation? {manager.is_valid_session(session_id1)}")

    # Test Case 3: Validate a non-existent session
    print("\n--- Test Case 3: Validate Non-existent Session ---")
    fake_session_id = str(uuid.uuid4())
    print(f"Is a fake session ID valid? {manager.is_valid_session(fake_session_id)}")

    # Test Case 4: Session expiration
    print("\n--- Test Case 4: Session Expiration ---")
    short_lived_manager = SessionManager(timeout_seconds=2)
    session_id2 = short_lived_manager.create_session("userB")
    print(f"Created short-lived session for userB: {session_id2}")
    print(f"Is session valid immediately? {short_lived_manager.is_valid_session(session_id2)}")
    print("Waiting for 3 seconds for session to expire...")
    time.sleep(3)
    print(f"Is session valid after expiration? {short_lived_manager.is_valid_session(session_id2)}")

    # Test Case 5: Attempt to create session with invalid username
    print("\n--- Test Case 5: Invalid Username ---")
    try:
        manager.create_session(None)
    except ValueError as e:
        print(f"Caught expected exception for null username: {e}")
    try:
        manager.create_session("   ")
    except ValueError as e:
        print(f"Caught expected exception for empty username: {e}")

if __name__ == "__main__":
    main()