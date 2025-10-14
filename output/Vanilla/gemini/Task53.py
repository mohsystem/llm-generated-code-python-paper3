import uuid

class SessionManager:
    def __init__(self):
        self.active_sessions = {}

    def create_session(self, username):
        """Creates a new session for a user and returns the session ID."""
        session_id = str(uuid.uuid4())
        self.active_sessions[session_id] = username
        print(f"Session created for {username} with ID: {session_id}")
        return session_id

    def get_user_from_session(self, session_id):
        """Retrieves the username for a given session ID."""
        return self.active_sessions.get(session_id)

    def end_session(self, session_id):
        """Ends an active session."""
        if session_id in self.active_sessions:
            username = self.active_sessions.pop(session_id)
            print(f"Session ended for {username} with ID: {session_id}")
        else:
            print(f"Session with ID {session_id} not found.")

    def is_session_active(self, session_id):
        """Checks if a session is currently active."""
        return session_id in self.active_sessions

def main():
    session_manager = SessionManager()
    print("--- Running Test Cases ---")

    # Test Case 1: Create a session for user 'alice'
    print("\n--- Test Case 1: Create Session ---")
    alice_session_id = session_manager.create_session("alice")

    # Test Case 2: Check if alice's session is active
    print("\n--- Test Case 2: Check Active Session ---")
    print(f"Is alice's session active? {session_manager.is_session_active(alice_session_id)}")

    # Test Case 3: Get user from session ID
    print("\n--- Test Case 3: Get User from Session ---")
    username = session_manager.get_user_from_session(alice_session_id)
    print(f"User for session {alice_session_id} is: {username}")

    # Test Case 4: Create another session for 'bob' and end 'alice's session
    print("\n--- Test Case 4: End Session ---")
    bob_session_id = session_manager.create_session("bob")
    session_manager.end_session(alice_session_id)

    # Test Case 5: Check if alice's session is still active and bob's is active
    print("\n--- Test Case 5: Verify Session Status ---")
    print(f"Is alice's session active after ending? {session_manager.is_session_active(alice_session_id)}")
    print(f"Is bob's session active? {session_manager.is_session_active(bob_session_id)}")
    non_existent_user = session_manager.get_user_from_session(alice_session_id)
    print(f"Attempting to get user from ended session: {non_existent_user}")


if __name__ == "__main__":
    main()