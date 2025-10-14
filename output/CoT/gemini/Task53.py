import secrets
import time

class SessionManager:
    # Set a short timeout for demonstration purposes (e.g., 3 seconds).
    SESSION_TIMEOUT = 3

    def __init__(self):
        # Dictionary to store active sessions: {session_id: {'username': str, 'created_at': float}}
        self.sessions = {}

    def create_session(self, username):
        """
        Creates a new session for a user.
        Generates a cryptographically secure, unique session ID.
        :param username: The username for whom to create the session.
        :return: The generated session ID.
        """
        if not username or not isinstance(username, str):
            return None

        # secrets.token_hex is recommended for generating secure tokens.
        session_id = secrets.token_hex(32)
        
        self.sessions[session_id] = {
            'username': username,
            'created_at': time.time()
        }
        print(f"Session created for {username} with ID: {session_id}")
        return session_id

    def is_session_valid(self, session_id):
        """
        Checks if a session is valid and not expired.
        :param session_id: The session ID to validate.
        :return: True if the session is valid, False otherwise.
        """
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]
        session_age = time.time() - session['created_at']

        if session_age > self.SESSION_TIMEOUT:
            # Session has expired, remove it.
            del self.sessions[session_id]
            print(f"Session {session_id} expired.")
            return False

        # In a real application, you might update a "last accessed" timestamp here.
        return True

    def invalidate_session(self, session_id):
        """
        Invalidates/removes a user session.
        :param session_id: The session ID to invalidate.
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            print(f"Session {session_id} invalidated.")
        else:
            print(f"Session {session_id} not found for invalidation.")

def main():
    """ Main function with test cases """
    session_manager = SessionManager()
    print("--- Session Management Test ---")

    # Test Case 1: Create a session and validate it
    print("\n--- Test Case 1: Create and Validate ---")
    user1_session_id = session_manager.create_session("user1")
    print(f"Is user1's session valid? {session_manager.is_session_valid(user1_session_id)}")

    # Test Case 2: Validate a non-existent session
    print("\n--- Test Case 2: Validate Non-Existent Session ---")
    print(f"Is 'invalid-session-id' valid? {session_manager.is_session_valid('invalid-session-id')}")

    # Test Case 3: Invalidate a session and check it again
    print("\n--- Test Case 3: Invalidate and Re-Validate ---")
    session_manager.invalidate_session(user1_session_id)
    print(f"Is user1's session valid after invalidation? {session_manager.is_session_valid(user1_session_id)}")

    # Test Case 4: Test session timeout
    print("\n--- Test Case 4: Session Timeout ---")
    user2_session_id = session_manager.create_session("user2")
    print(f"Is user2's session valid immediately? {session_manager.is_session_valid(user2_session_id)}")
    print(f"Waiting for {SessionManager.SESSION_TIMEOUT + 1} seconds to test timeout...")
    time.sleep(SessionManager.SESSION_TIMEOUT + 1)
    print(f"Is user2's session valid after timeout? {session_manager.is_session_valid(user2_session_id)}")
    
    # Test Case 5: Create multiple sessions
    print("\n--- Test Case 5: Multiple Sessions ---")
    user3_session_id = session_manager.create_session("user3")
    user4_session_id = session_manager.create_session("user4")
    print(f"Is user3's session valid? {session_manager.is_session_valid(user3_session_id)}")
    print(f"Is user4's session valid? {session_manager.is_session_valid(user4_session_id)}")
    session_manager.invalidate_session(user3_session_id)
    print(f"Is user3's session valid after invalidation? {session_manager.is_session_valid(user3_session_id)}")
    print(f"Is user4's session still valid? {session_manager.is_session_valid(user4_session_id)}")

if __name__ == "__main__":
    main()