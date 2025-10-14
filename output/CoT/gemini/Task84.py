import uuid
import secrets

def generate_session_id():
    """
    Generates a random and unique session ID using Python's uuid module.
    UUID version 4 is based on random numbers and is suitable for session IDs.
    
    Returns:
        str: A unique session ID string.
    """
    return str(uuid.uuid4())

def generate_secure_session_id(length=32):
    """
    An alternative method using the secrets module, which is designed for
    generating cryptographically strong random numbers for managing secrets.
    
    Args:
        length (int): The number of bytes of randomness to generate.
    
    Returns:
        str: A URL-safe text string containing random bytes.
    """
    return secrets.token_urlsafe(length)

if __name__ == "__main__":
    print("--- Testing generate_session_id() [uuid] ---")
    for i in range(5):
        session_id = generate_session_id()
        print(f"Test Case {i + 1}: {session_id}")
        
    print("\n--- Testing generate_secure_session_id(24) [secrets] ---")
    for i in range(5):
        session_id = generate_secure_session_id(24) # 24 bytes = 192 bits
        print(f"Test Case {i + 1}: {session_id}")