import os
import secrets

class SessionManager:
    """
    A class to manage user sessions securely in a web application context.
    This is a simplified in-memory implementation.
    """
    def __init__(self):
        # In a real application, use a persistent, scalable store like Redis.
        self._sessions = {}

    def _generate_session_id(self):
        """Generates a cryptographically strong, URL-safe session ID."""
        # secrets.token_urlsafe provides 32 bytes of entropy by default.
        return secrets.token_urlsafe(32)

    def create_session(self, username: str) -> str:
        """
        Creates a new session for a user and returns the session ID.
        """
        if not username:
            raise ValueError("Username cannot be empty.")
        
        session_id = self._generate_session_id()
        # Store user data associated with the session. In a real app,
        # this could be a dictionary with user ID, roles, creation time, etc.
        self._sessions[session_id] = {'username': username}
        return session_id

    def get_session_user(self, session_id: str) -> str or None:
        """
        Retrieves the username for a given session ID.
        Returns None if the session is not valid.
        """
        if session_id is None or session_id not in self._sessions:
            return None
        
        # In a real app, you would also check for session expiration here.
        session_data = self._sessions.get(session_id)
        return session_data.get('username')

    def invalidate_session(self, session_id: str):
        """
        Terminates a session by removing it from the store.
        """
        if session_id in self._sessions:
            del self._sessions[session_id]

def main():
    """Main function with test cases."""
    session_manager = SessionManager()
    print("--- Secure Session Management Test ---")

    # Test Case 1: Create a session for user 'alice'
    print("\n1. Creating session for 'alice'...")
    alice_session_id = session_manager.create_session("alice")
    print(f"   Alice's session ID created: {alice_session_id}")
    user = session_manager.get_session_user(alice_session_id)
    print(f"   Verified user for session ID: {user}")
    assert user == "alice"

    # Test Case 2: Create a session for user 'bob'
    print("\n2. Creating session for 'bob'...")
    bob_session_id = session_manager.create_session("bob")
    print(f"   Bob's session ID created: {bob_session_id}")
    user = session_manager.get_session_user(bob_session_id)
    print(f"   Verified user for session ID: {user}")
    assert user == "bob"

    # Test Case 3: Validate an invalid/non-existent session ID
    print("\n3. Validating a non-existent session ID...")
    fake_session_id = "invalid-session-id-12345"
    user = session_manager.get_session_user(fake_session_id)
    print(f"   User for fake session ID: {user}")
    assert user is None

    # Test Case 4: Invalidate Alice's session and try to use it again
    print("\n4. Invalidating Alice's session...")
    session_manager.invalidate_session(alice_session_id)
    print("   Alice's session has been invalidated.")
    user = session_manager.get_session_user(alice_session_id)
    print(f"   Attempting to verify Alice's old session ID: {user}")
    assert user is None

    # Test Case 5: Ensure Bob's session is still valid
    print("\n5. Verifying Bob's session is still active...")
    user = session_manager.get_session_user(bob_session_id)
    print(f"   User for Bob's session ID: {user}")
    assert user == "bob"

    print("\n--- All test cases passed ---")

if __name__ == "__main__":
    main()