import secrets
import sys

def generate_session_id():
    """
    Generates a cryptographically secure, random and unique session ID.
    The `secrets` module is used as it is suitable for managing secrets
    such as account authentication tokens, and session keys.
    
    Returns:
        A random 32-character hexadecimal session ID string.
    """
    # 16 bytes = 128 bits, which results in a 32-character hex string.
    # This provides 2^128 possible IDs, making collisions extremely unlikely.
    try:
        return secrets.token_hex(16)
    except Exception as e:
        print(f"Error generating session ID: {e}", file=sys.stderr)
        return ""

if __name__ == "__main__":
    print("Python: Generating 5 unique session IDs")
    for i in range(5):
        session_id = generate_session_id()
        print(f"Session ID {i + 1}: {session_id}")