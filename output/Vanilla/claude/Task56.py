
import secrets
import hashlib
import base64
import time

def generate_token(username, timestamp):
    try:
        random_bytes = secrets.token_bytes(32)
        
        data = f"{username}:{timestamp}:{base64.urlsafe_b64encode(random_bytes).decode().rstrip('=')}"
        
        hash_object = hashlib.sha256(data.encode('utf-8'))
        hash_bytes = hash_object.digest()
        
        token = base64.urlsafe_b64encode(hash_bytes).decode().rstrip('=')
        return token
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    print("Test Case 1:")
    token1 = generate_token("user123", int(time.time() * 1000))
    print(f"Token for user123: {token1}")
    
    print("\\nTest Case 2:")
    token2 = generate_token("admin", int(time.time() * 1000))
    print(f"Token for admin: {token2}")
    
    print("\\nTest Case 3:")
    token3 = generate_token("testuser@email.com", int(time.time() * 1000))
    print(f"Token for testuser@email.com: {token3}")
    
    print("\\nTest Case 4:")
    token4 = generate_token("john_doe", 1234567890000)
    print(f"Token for john_doe with fixed timestamp: {token4}")
    
    print("\\nTest Case 5:")
    token5 = generate_token("guest", int(time.time() * 1000))
    print(f"Token for guest: {token5}")
