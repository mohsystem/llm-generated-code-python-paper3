import os
import time
import secrets
from dataclasses import dataclass

# Session duration in seconds (e.g., 30 minutes)
SESSION_DURATION_SECONDS = 1800

@dataclass
class Session:
    user_id: str
    expiration_time: float

    def is_expired(self) -> bool:
        """Check if the session has expired."""
        return time.time() > self.expiration_time

class SessionManager:
    """
    Securely manages user sessions in-memory.
    Uses cryptographically strong random tokens for session IDs.
    Sessions expire after a defined duration.
    """
    def __init__(self):
        self._active_sessions = {}

    def _generate_secure_session_id(self) -> str:
        """Generates a cryptographically secure, URL-safe session ID."""
        return secrets.token_urlsafe(32)

    def create_session(self, user_id: str) -> str:
        """
        Creates a new session for a given user.
        :param user_id: The ID of the user.
        :return: The generated session ID.
        """
        if not user_id:
            raise ValueError("User ID cannot be empty.")
        
        session_id = self._generate_secure_session_id()
        expiration_time = time.time() + SESSION_DURATION_SECONDS
        session = Session(user_id=user_id, expiration_time=expiration_time)
        self._active_sessions[session_id] = session
        return session_id

    def get_session_user(self, session_id: str) -> str | None:
        """
        Retrieves the user ID for a session if it's valid and not expired.
        :param session_id: The session ID to check.
        :return: The user ID if the session is valid, otherwise None.
        """
        if session_id is None:
            return None
            
        session = self._active_sessions.get(session_id)

        if session is None:
            return None  # Session not found

        if session.is_expired():
            # Clean up expired session
            del self._active_sessions[session_id]
            return None

        return session.user_id

    def end_session(self, session_id: str):
        """
        Invalidates and removes a session.
        :param session_id: The ID of the session to end.
        """
        if session_id in self._active_sessions:
            del self._active_sessions[session_id]

def main():
    """Main function with test cases for the SessionManager."""
    sm = SessionManager()
    print("--- Session Management Test Cases ---")

    # Test Case 1: Create a new session for 'bob'
    print("\n1. Creating session for user 'bob'...")
    bob_session_id = sm.create_session("bob")
    print(f"   Session created for bob with ID: {bob_session_id}")

    # Test Case 2: Validate 'bob's' session
    print("\n2. Validating bob's session...")
    user = sm.get_session_user(bob_session_id)
    if user:
        print(f"   Success! Session is valid for user: {user}")
    else:
        print("   Failure! Session is not valid.")

    # Test Case 3: Validate a non-existent session ID
    print("\n3. Validating a fake session ID...")
    fake_session_id = "fake-session-id-abcdef"
    user = sm.get_session_user(fake_session_id)
    if user:
        print(f"   Failure! Fake session was validated for user: {user}")
    else:
        print("   Success! Fake session was correctly identified as invalid.")

    # Test Case 4: End 'bob's' session
    print("\n4. Ending bob's session...")
    sm.end_session(bob_session_id)
    print(f"   Session {bob_session_id} has been ended.")

    # Test Case 5: Re-validate 'bob's' ended session
    print("\n5. Re-validating bob's ended session...")
    user = sm.get_session_user(bob_session_id)
    if user:
        print(f"   Failure! Ended session was validated for user: {user}")
    else:
        print("   Success! Ended session is no longer valid.")

if __name__ == "__main__":
    main()