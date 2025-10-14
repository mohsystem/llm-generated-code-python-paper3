
import secrets
import hashlib
import base64
import time

class Task56:
    TOKEN_LENGTH = 32
    
    @staticmethod
    def generate_token(user_id, timestamp=None):
        """\n        Generate a secure authentication token for a user.\n        \n        Args:\n            user_id: The user identifier\n            timestamp: Optional timestamp (uses current time if not provided)\n            \n        Returns:\n            A secure token string encoded in Base64\n        """
        if timestamp is None:
            timestamp = int(time.time() * 1000)
        
        # Generate cryptographically secure random bytes
        random_bytes = secrets.token_bytes(Task56.TOKEN_LENGTH)
        
        # Combine user_id, timestamp, and random bytes
        combined_data = f"{user_id}:{timestamp}:{base64.b64encode(random_bytes).decode('utf-8')}"
        
        # Hash the combined data using SHA-256
        hash_object = hashlib.sha256(combined_data.encode('utf-8'))
        hash_bytes = hash_object.digest()
        
        # Encode to Base64 for safe transmission
        token = base64.urlsafe_b64encode(hash_bytes).decode('utf-8').rstrip('=')
        
        return token


def main():
    task = Task56()
    
    # Test case 1: Generate token for user1
    token1 = task.generate_token("user1")
    print(f"Test 1 - Token for user1: {token1}")
    
    # Test case 2: Generate token for user2
    token2 = task.generate_token("user2")
    print(f"Test 2 - Token for user2: {token2}")
    
    # Test case 3: Generate token with specific timestamp
    specific_timestamp = 1700000000000
    token3 = task.generate_token("user3", specific_timestamp)
    print(f"Test 3 - Token for user3 with timestamp: {token3}")
    
    # Test case 4: Verify tokens are unique for same user
    token4a = task.generate_token("user4")
    time.sleep(0.01)  # Small delay to ensure different timestamp
    token4b = task.generate_token("user4")
    print(f"Test 4 - Two tokens for user4 are different: {token4a != token4b}")
    
    # Test case 5: Generate token for admin user
    token5 = task.generate_token("admin")
    print(f"Test 5 - Token for admin: {token5}")


if __name__ == "__main__":
    main()
