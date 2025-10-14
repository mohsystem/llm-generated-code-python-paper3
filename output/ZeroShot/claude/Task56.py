
import secrets
import hashlib
import base64
import time

def generate_token(user_id):
    random_bytes = secrets.token_bytes(32)
    timestamp = str(int(time.time() * 1000))
    data_to_hash = user_id + timestamp + base64.b64encode(random_bytes).decode('utf-8')
    
    hash_object = hashlib.sha256(data_to_hash.encode('utf-8'))
    hash_bytes = hash_object.digest()
    
    token = base64.urlsafe_b64encode(hash_bytes).decode('utf-8').rstrip('=')
    return token

if __name__ == "__main__":
    print("Test Case 1:")
    token1 = generate_token("user123")
    print(f"Token for user123: {token1}")
    
    print("\\nTest Case 2:")
    token2 = generate_token("admin@example.com")
    print(f"Token for admin@example.com: {token2}")
    
    print("\\nTest Case 3:")
    token3 = generate_token("testUser456")
    print(f"Token for testUser456: {token3}")
    
    print("\\nTest Case 4:")
    token4 = generate_token("john.doe")
    print(f"Token for john.doe: {token4}")
    
    print("\\nTest Case 5:")
    token5 = generate_token("user123")
    print(f"Token for user123 (second generation): {token5}")
    print(f"Tokens are unique: {token1 != token5}")
