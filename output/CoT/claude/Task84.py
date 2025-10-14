
import secrets
import base64

def generate_session_id():
    """Generate a cryptographically secure random session ID"""
    # Generate 32 random bytes (256 bits)
    random_bytes = secrets.token_bytes(32)
    
    # Encode to URL-safe base64 and remove padding
    session_id = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')
    
    return session_id

def main():
    print("Generating 5 unique session IDs:\\n")
    
    for i in range(1, 6):
        session_id = generate_session_id()
        print(f"Session ID {i}: {session_id}")
        print(f"Length: {len(session_id)} characters\\n")

if __name__ == "__main__":
    main()
