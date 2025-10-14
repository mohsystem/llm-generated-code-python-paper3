import secrets
import time
import threading
from dataclasses import dataclass
from typing import Dict, Optional

@dataclass
class SessionData:
    """Holds data for a single user session."""
    username: str
    creation_time: float

class SessionManager:
    """
    Manages user sessions in a thread-safe manner.
    Session IDs are generated using a cryptographically secure random number generator.
    """
    _SESSION_ID_BYTES = 32

    def __init__(self, session_timeout_seconds: int):
        if session_timeout_seconds <= 0:
            raise ValueError("Session timeout must be positive.")
        self.session_timeout_seconds = session_timeout_seconds
        self._sessions: Dict[str, SessionData] = {}
        self._lock = threading.Lock()

    def create_session(self, username: str) -> str:
        """
        Creates a new session for the given username.
        :param username: The username to associate with the session. Cannot be null or empty.
        :return: A unique, secure session ID as a hex string.
        """
        if not username or not username.strip():
            raise ValueError("Username cannot be null or empty.")
        
        session_id = secrets.token_hex(self._SESSION_ID_BYTES)
        
        with self._lock:
            self._sessions[session_id] = SessionData(
                username=username,
                creation_time=time.monotonic()
            )
        return session_id

    def _get_valid_session(self, session_id: str) -> Optional[SessionData]:
        if not session_id:
            return None
            
        with self._lock:
            session_data = self._sessions.get(session_id)
            if not session_data:
                return None
            
            now = time.monotonic()
            if now >= session_data.creation_time + self.session_timeout_seconds:
                # Eagerly remove expired session to prevent reuse
                del self._sessions[session_id]
                return None
            
            return session_data

    def is_valid_session(self, session_id: str) -> bool:
        """
        Checks if a session ID is valid and not expired.
        :param session_id: The session ID to validate.
        :return: True if the session is valid, False otherwise.
        """
        return self._get_valid_session(session_id) is not None

    def get_session_user(self, session_id: str) -> Optional[str]:
        """
        Retrieves the username associated with a valid session.
        :param session_id: The session ID.
        :return: The username if the session is valid, or None.
        """
        session_data = self._get_valid_session(session_id)
        return session_data.username if session_data else None

    def end_session(self, session_id: str) -> None:
        """
        Ends and removes a session.
        :param session_id: The session ID to end.
        """
        if not session_id:
            return
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]

def main():
    """Main function with test cases."""
    # Test case 1: Create and validate a new session
    print("--- Test Case 1: Create and Validate Session ---")
    manager = SessionManager(session_timeout_seconds=1800)
    alice_session_id = manager.create_session("alice")
    print(f"Created session for alice: {alice_session_id}")
    print(f"Is alice's session valid? {manager.is_valid_session(alice_session_id)}")
    print(f"User for session: {manager.get_session_user(alice_session_id)}")
    print()

    # Test case 2: Validate a non-existent session
    print("--- Test Case 2: Validate Non-existent Session ---")
    fake_session_id = "fakeSessionId12345"
    print(f"Is fake session valid? {manager.is_valid_session(fake_session_id)}")
    print(f"User for fake session: {manager.get_session_user(fake_session_id)}")
    print()

    # Test case 3: Invalidate a session by ending it
    print("--- Test Case 3: End Session ---")
    bob_session_id = manager.create_session("bob")
    print(f"Created session for bob: {bob_session_id}")
    print(f"Is bob's session valid before ending? {manager.is_valid_session(bob_session_id)}")
    manager.end_session(bob_session_id)
    print("Ended bob's session.")
    print(f"Is bob's session valid after ending? {manager.is_valid_session(bob_session_id)}")
    print()
    
    # Test case 4: Session expiration
    print("--- Test Case 4: Session Expiration ---")
    short_lived_manager = SessionManager(session_timeout_seconds=2)
    charlie_session_id = short_lived_manager.create_session("charlie")
    print(f"Created short-lived session for charlie: {charlie_session_id}")
    print(f"Is charlie's session valid immediately? {short_lived_manager.is_valid_session(charlie_session_id)}")
    print("Waiting for 3 seconds...")
    time.sleep(3)
    print(f"Is charlie's session valid after 3 seconds? {short_lived_manager.is_valid_session(charlie_session_id)}")
    print()

    # Test case 5: Attempt to create session with invalid username
    print("--- Test Case 5: Invalid Username ---")
    try:
        manager.create_session("")
    except ValueError as e:
        print(f"Caught expected exception for empty username: {e}")
    try:
        manager.create_session("   ")
    except ValueError as e:
        print(f"Caught expected exception for whitespace username: {e}")

if __name__ == "__main__":
    main()