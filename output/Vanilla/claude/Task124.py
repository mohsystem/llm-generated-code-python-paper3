
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64

class Task124:
    def __init__(self):
        # In production, use proper key management
        self.key = get_random_bytes(16)
        self.encrypted_data = {}
    
    def encrypt_data(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_data = pad(data.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted).decode()
    
    def decrypt_data(self, encrypted_data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        decoded = base64.b64decode(encrypted_data)
        decrypted = cipher.decrypt(decoded)
        return unpad(decrypted, AES.block_size).decode()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def store_secure_data(self, key, value):
        encrypted = self.encrypt_data(value)
        self.encrypted_data[key] = encrypted
    
    def retrieve_secure_data(self, key):
        if key not in self.encrypted_data:
            return None
        return self.decrypt_data(self.encrypted_data[key])

if __name__ == "__main__":
    secure = Task124()
    
    # Test Case 1: Basic encryption/decryption
    print("Test 1: Basic encryption/decryption")
    secure.store_secure_data("user1", "1234-XXXX-XXXX-5678")
    print(f"Retrieved: {secure.retrieve_secure_data('user1')}")
    
    # Test Case 2: Hash password
    print("\\nTest 2: Password hashing")
    hashed_pwd = secure.hash_password("myPassword123")
    print(f"Hashed password: {hashed_pwd[:40]}...")
    
    # Test Case 3: Store multiple records
    print("\\nTest 3: Multiple records")
    secure.store_secure_data("user2", "9876-XXXX-XXXX-5432")
    secure.store_secure_data("user3", "5555-XXXX-XXXX-1111")
    print(f"User2: {secure.retrieve_secure_data('user2')}")
    print(f"User3: {secure.retrieve_secure_data('user3')}")
    
    # Test Case 4: Non-existent key
    print("\\nTest 4: Non-existent key")
    print(f"User4: {secure.retrieve_secure_data('user4')}")
    
    # Test Case 5: Verify encryption
    print("\\nTest 5: Verify data is encrypted")
    secure.store_secure_data("test", "SensitiveData123")
    print(f"Original stored (encrypted): {secure.encrypted_data['test'][:28]}...")
    print(f"Retrieved (decrypted): {secure.retrieve_secure_data('test')}")
