import uuid
import time

# In-memory dictionary to store sessions
# Format: {session_id: {'username': username, 'creation_time': timestamp}}
_session_store = {}

def create_session(username: str) -> str:
    """Creates a new session for a given user and returns the session ID."""
    session_id = str(uuid.uuid4())
    _session_store[session_id] = {
        'username': username,
        'creation_time': time.time()
    }
    print(f"Session created for {username} with ID: {session_id}")
    return session_id

def get_session_user(session_id: str) -> str or None:
    """Retrieves the username for a given session ID if it's valid."""
    session = _session_store.get(session_id)
    if session:
        return session.get('username')
    return None

def invalidate_session(session_id: str):
    """Invalidates/removes a user session."""
    if session_id in _session_store:
        del _session_store[session_id]
        print(f"Session invalidated: {session_id}")
    else:
        print(f"Session to invalidate not found: {session_id}")

def is_session_valid(session_id: str) -> bool:
    """Checks if a session ID is currently valid."""
    return session_id in _session_store

def main():
    """Main function with 5 test cases."""
    print("--- Starting Session Management Test ---")

    # Test Case 1: Create a session for user "alice"
    print("\n[Test Case 1: Create session for alice]")
    alice_session_id = create_session("alice")

    # Test Case 2: Check if alice's session is valid and get her username
    print("\n[Test Case 2: Validate alice's session]")
    print(f"Is alice's session valid? {is_session_valid(alice_session_id)}")
    username = get_session_user(alice_session_id)
    print(f"Retrieved user for session {alice_session_id}: {username}")

    # Test Case 3: Create a second session for user "bob"
    print("\n[Test Case 3: Create session for bob]")
    bob_session_id = create_session("bob")
    print(f"Is bob's session valid? {is_session_valid(bob_session_id)}")

    # Test Case 4: Invalidate alice's session and verify
    print("\n[Test Case 4: Invalidate alice's session]")
    invalidate_session(alice_session_id)
    print(f"Is alice's session now valid? {is_session_valid(alice_session_id)}")
    print(f"Attempting to get user for invalidated session: {get_session_user(alice_session_id)}")

    # Test Case 5: Verify that bob's session is still valid
    print("\n[Test Case 5: Verify bob's session is unaffected]")
    print(f"Is bob's session still valid? {is_session_valid(bob_session_id)}")
    print(f"Retrieved user for bob's session: {get_session_user(bob_session_id)}")

    print("\n--- Session Management Test Finished ---")

if __name__ == "__main__":
    main()