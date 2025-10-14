
import secrets
import base64
from typing import Set

_used_session_ids: Set[str] = set()
SESSION_ID_BYTES: int = 32


def generate_session_id() -> str:
    """\n    Generates a cryptographically secure random and unique session ID.\n    \n    Returns:\n        str: A Base64-encoded session ID string\n    """
    while True:
        random_bytes = secrets.token_bytes(SESSION_ID_BYTES)
        session_id = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
        
        if session_id not in _used_session_ids:
            _used_session_ids.add(session_id)
            return session_id


def main() -> None:
    print("Generating 5 unique session IDs:")
    for i in range(1, 6):
        session_id = generate_session_id()
        print(f"Session ID {i}: {session_id}")
        print(f"Length: {len(session_id)} characters")
    
    print(f"\\nTotal unique session IDs generated: {len(_used_session_ids)}")


if __name__ == "__main__":
    main()
