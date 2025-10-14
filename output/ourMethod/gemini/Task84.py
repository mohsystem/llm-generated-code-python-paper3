import secrets
import typing

# Use 32 bytes of entropy for the session ID, which is a secure default.
SESSION_ID_BYTES = 32

def generate_session_id() -> str:
    """
    Generates a cryptographically secure, random and unique session ID.
    The `secrets` module is used to ensure the ID is unpredictable.
    The ID has 32 bytes of entropy and is encoded in a URL-safe format.

    :return: A URL-safe string representing the session ID.
    """
    return secrets.token_urlsafe(SESSION_ID_BYTES)

def main() -> None:
    """
    Main function to demonstrate session ID generation with 5 test cases.
    """
    print("Generating 5 random and unique session IDs:")
    for i in range(5):
        session_id = generate_session_id()
        print(f"Session ID {i + 1}: {session_id}")
        if not session_id or not isinstance(session_id, str):
            print(f"Test case {i + 1} failed: Generated session ID is invalid.")


if __name__ == "__main__":
    main()