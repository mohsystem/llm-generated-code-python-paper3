
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class Task134:
    def __init__(self):
        self.key_store = {}
        self.KEY_SIZE = 32  # 256 bits
        self.NONCE_SIZE = 12  # 96 bits for GCM
    
    def generate_key(self, key_id):
        """Generate a new AES key"""
        try:
            key = os.urandom(self.KEY_SIZE)
            self.key_store[key_id] = key
            return f"Key generated successfully: {key_id}"
        except Exception as e:
            return f"Error generating key: {str(e)}"
    
    def encrypt(self, key_id, plaintext):
        """Encrypt data using a stored key"""
        try:
            if key_id not in self.key_store:
                return f"Key not found: {key_id}"
            
            key = self.key_store[key_id]
            aesgcm = AESGCM(key)
            nonce = os.urandom(self.NONCE_SIZE)
            
            plaintext_bytes = plaintext.encode('utf-8')
            ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
            
            # Combine nonce and ciphertext
            combined = nonce + ciphertext
            return base64.b64encode(combined).decode('utf-8')
        except Exception as e:
            return f"Encryption error: {str(e)}"
    
    def decrypt(self, key_id, encrypted_data):
        """Decrypt data using a stored key"""
        try:
            if key_id not in self.key_store:
                return f"Key not found: {key_id}"
            
            key = self.key_store[key_id]
            aesgcm = AESGCM(key)
            
            combined = base64.b64decode(encrypted_data)
            nonce = combined[:self.NONCE_SIZE]
            ciphertext = combined[self.NONCE_SIZE:]
            
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            return f"Decryption error: {str(e)}"
    
    def delete_key(self, key_id):
        """Delete a key from the store"""
        if key_id in self.key_store:
            del self.key_store[key_id]
            return f"Key deleted: {key_id}"
        return f"Key not found: {key_id}"
    
    def list_keys(self):
        """List all key IDs"""
        return list(self.key_store.keys())


def main():
    key_manager = Task134()
    
    # Test Case 1: Generate a key
    print("Test 1 - Generate Key:")
    print(key_manager.generate_key("key1"))
    print()
    
    # Test Case 2: Encrypt data
    print("Test 2 - Encrypt Data:")
    encrypted = key_manager.encrypt("key1", "Hello, Secure World!")
    print(f"Encrypted: {encrypted}")
    print()
    
    # Test Case 3: Decrypt data
    print("Test 3 - Decrypt Data:")
    decrypted = key_manager.decrypt("key1", encrypted)
    print(f"Decrypted: {decrypted}")
    print()
    
    # Test Case 4: List all keys
    print("Test 4 - List Keys:")
    key_manager.generate_key("key2")
    key_manager.generate_key("key3")
    print(f"Keys: {key_manager.list_keys()}")
    print()
    
    # Test Case 5: Delete a key
    print("Test 5 - Delete Key:")
    print(key_manager.delete_key("key2"))
    print(f"Remaining keys: {key_manager.list_keys()}")


if __name__ == "__main__":
    main()
