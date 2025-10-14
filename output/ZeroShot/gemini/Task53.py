import time
import secrets
from typing import Optional

# Use a short timeout for demonstration purposes
SESSION_TIMEOUT_SECONDS = 10 

class Session:
    """Represents a single user session."""
    def __init__(self, session_id: str, username: str):
        self.session_id = session_id
        self.username = username
        self.creation_time = time.time()
        self.last_accessed_time = self.creation_time

    def update_last_accessed_time(self):
        """Updates the session's last access time to the current time."""
        self.last_accessed_time = time.time()

    def __str__(self):
        return f"Session(id={self.session_id}, user={self.username})"

class SessionManager:
    """Manages the lifecycle of user sessions."""
    # In a real multi-process/multi-threaded app, this would need a thread-safe
    # dictionary or an external store like Redis.
    _active_sessions = {}

    def create_session(self, username: str) -> str:
        """
        Creates a new session for a user.
        Returns a cryptographically secure session ID.
        """
        if not username:
            raise ValueError("Username cannot be empty.")
        # Generates a cryptographically secure URL-safe text string.
        session_id = secrets.token_urlsafe(32)
        session = Session(session_id, username)
        self._active_sessions[session_id] = session
        return session_id

    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieves a session if it exists and is not expired.
        Returns the Session object if valid, otherwise None.
        """
        if not session_id:
            return None
            
        session = self._active_sessions.get(session_id)
        if not session:
            return None

        now = time.time()
        if now - session.last_accessed_time > SESSION_TIMEOUT_SECONDS:
            # Session expired, remove it.
            del self._active_sessions[session_id]
            return None

        session.update_last_accessed_time()
        return session

    def invalidate_session(self, session_id: str):
        """Deletes/invalidates a session."""
        if session_id in self._active_sessions:
            del self._active_sessions[session_id]

class Task53:
    @staticmethod
    def run_tests():
        print("--- Session Management Test ---")
        manager = SessionManager()

        # Test Case 1: Create and validate a session
        print("\n--- Test Case 1: Create and Validate Session ---")
        alice_session_id = manager.create_session("alice")
        print(f"Created session for 'alice': {alice_session_id}")
        session = manager.get_session(alice_session_id)
        if session:
            print(f"Session is valid. User: {session.username}")
        else:
            print("Session is invalid.")

        # Test Case 2: Invalidate a session
        print("\n--- Test Case 2: Invalidate Session ---")
        bob_session_id = manager.create_session("bob")
        print(f"Created session for 'bob': {bob_session_id}")
        manager.invalidate_session(bob_session_id)
        print("Invalidated session for 'bob'.")
        session = manager.get_session(bob_session_id)
        if session:
            print("Error: Session for 'bob' should be invalid.")
        else:
            print("Session for 'bob' is correctly invalidated.")

        # Test Case 3: Session timeout
        print("\n--- Test Case 3: Session Timeout ---")
        charlie_session_id = manager.create_session("charlie")
        print(f"Created session for 'charlie': {charlie_session_id}")
        print(f"Waiting for session to time out (more than {SESSION_TIMEOUT_SECONDS} seconds)...")
        time.sleep(SESSION_TIMEOUT_SECONDS + 1)
        session = manager.get_session(charlie_session_id)
        if session:
            print("Error: Session for 'charlie' should have timed out.")
        else:
            print("Session for 'charlie' correctly timed out.")
            
        # Test Case 4: Accessing invalid/non-existent session
        print("\n--- Test Case 4: Access Invalid Session ---")
        session = manager.get_session("invalid-session-id")
        if session:
            print("Error: A non-existent session was found.")
        else:
            print("Correctly handled non-existent session ID.")
            
        # Test Case 5: Session activity extends lifetime
        print("\n--- Test Case 5: Session Activity Extends Lifetime ---")
        dave_session_id = manager.create_session("dave")
        print(f"Created session for 'dave': {dave_session_id}")
        print(f"Waiting for {SESSION_TIMEOUT_SECONDS - 3} seconds...")
        time.sleep(SESSION_TIMEOUT_SECONDS - 3)
        session = manager.get_session(dave_session_id)
        if session:
            print("Accessed session for 'dave' successfully. Lifetime should be extended.")
        else:
            print("Error: Session for 'dave' expired prematurely.")
            
        print(f"Waiting for another {SESSION_TIMEOUT_SECONDS - 3} seconds...")
        time.sleep(SESSION_TIMEOUT_SECONDS - 3)
        session = manager.get_session(dave_session_id)
        if session:
            print(f"Session for 'dave' is still valid after {2 * (SESSION_TIMEOUT_SECONDS - 3)} seconds due to activity.")
        else:
            print("Error: Session for 'dave' expired despite recent activity.")
        
if __name__ == "__main__":
    Task53.run_tests()