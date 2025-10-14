import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

@dataclass
class Session:
    """Represents a user session."""
    user_id: str
    expiration_time: datetime
    creation_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class SessionManager:
    """Manages user sessions securely in memory."""

    def __init__(self, session_lifetime: timedelta = timedelta(minutes=30)):
        self._sessions: Dict[str, Session] = {}
        self.SESSION_LIFETIME = session_lifetime
        self.SESSION_ID_BYTES = 32

    def _generate_session_id(self) -> str:
        """Generates a cryptographically secure, URL-safe session ID."""
        return secrets.token_urlsafe(self.SESSION_ID_BYTES)

    def create_session(self, user_id: str, lifetime: Optional[timedelta] = None) -> str:
        """
        Creates a new session for a given user.
        
        Args:
            user_id: The identifier for the user.
            lifetime: Optional custom lifetime for the session.
        
        Returns:
            The newly created session ID.
        """
        if not user_id:
            raise ValueError("User ID cannot be empty.")
        
        session_id = self._generate_session_id()
        now = datetime.now(timezone.utc)
        session_lifetime = lifetime if lifetime is not None else self.SESSION_LIFETIME
        expiration = now + session_lifetime
        
        session = Session(user_id=user_id, expiration_time=expiration, creation_time=now)
        self._sessions[session_id] = session
        return session_id

    def get_user_id_from_session(self, session_id: str) -> Optional[str]:
        """
        Retrieves the user ID associated with a session ID, if the session is valid and not expired.
        
        Args:
            session_id: The session ID to validate.
        
        Returns:
            The user ID if the session is valid, otherwise None.
        """
        if not session_id:
            return None
            
        session = self._sessions.get(session_id)
        if not session:
            return None

        if datetime.now(timezone.utc) > session.expiration_time:
            # Eagerly remove expired session
            del self._sessions[session_id]
            return None
        
        return session.user_id

    def terminate_session(self, session_id: str) -> None:
        """
        Terminates a session, effectively logging the user out.
        
        Args:
            session_id: The session ID to terminate.
        """
        if session_id in self._sessions:
            del self._sessions[session_id]

def main():
    """Main function with test cases."""
    session_manager = SessionManager()

    print("--- Test Case 1: Session Creation and Validation ---")
    session_id_1 = session_manager.create_session("user123")
    print(f"Created session for user123: {session_id_1}")
    user_id = session_manager.get_user_id_from_session(session_id_1)
    if user_id:
        print(f"Session is valid. User ID: {user_id}")
    
    print("\n--- Test Case 2: Validation of Non-Existent Session ---")
    fake_session_id = "nonexistent-session-id"
    result_2 = session_manager.get_user_id_from_session(fake_session_id)
    print(f"Validation for fake session '{fake_session_id}': {'Valid' if result_2 else 'Invalid'}")

    print("\n--- Test Case 3: Session Termination ---")
    session_id_3 = session_manager.create_session("user456")
    print(f"Created session for user456: {session_id_3}")
    session_manager.terminate_session(session_id_3)
    print("Terminated session for user456.")
    result_3 = session_manager.get_user_id_from_session(session_id_3)
    print(f"Validation after termination: {'Valid' if result_3 else 'Invalid'}")

    print("\n--- Test Case 4: Session Expiration ---")
    session_id_4 = session_manager.create_session("user789", lifetime=timedelta(seconds=2))
    print(f"Created short-lived session for user789: {session_id_4}")
    print("Waiting for 3 seconds for session to expire...")
    time.sleep(3)
    result_4 = session_manager.get_user_id_from_session(session_id_4)
    print(f"Validation after expiration: {'Valid' if result_4 else 'Invalid'}")

    print("\n--- Test Case 5: Multiple Concurrent Sessions ---")
    user_a_session = session_manager.create_session("userA")
    user_b_session = session_manager.create_session("userB")
    print(f"Created session for userA: {user_a_session}")
    print(f"Created session for userB: {user_b_session}")
    user_a_result = session_manager.get_user_id_from_session(user_a_session)
    user_b_result = session_manager.get_user_id_from_session(user_b_session)
    print(f"User A session validation: {user_a_result or 'Invalid'}")
    print(f"User B session validation: {user_b_result or 'Invalid'}")
    session_manager.terminate_session(user_a_session)
    print("Terminated session for userA.")
    user_a_result = session_manager.get_user_id_from_session(user_a_session)
    user_b_result = session_manager.get_user_id_from_session(user_b_session)
    print(f"User A session validation after termination: {user_a_result or 'Invalid'}")
    print(f"User B session validation (should still be valid): {user_b_result or 'Invalid'}")

if __name__ == "__main__":
    main()