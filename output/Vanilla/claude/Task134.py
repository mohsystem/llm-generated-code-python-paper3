
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import List, Optional

class Task134:
    def __init__(self):
        self.key_store = {}
    
    def generate_key(self, key_id: str, key_size: int) -> str:
        try:
            key_bytes = os.urandom(key_size // 8)
            encoded_key = base64.b64encode(key_bytes).decode('utf-8')
            self.key_store[key_id] = encoded_key
            return encoded_key
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_key(self, key_id: str) -> str:
        return self.key_store.get(key_id, "Key not found")
    
    def delete_key(self, key_id: str) -> bool:
        if key_id in self.key_store:
            del self.key_store[key_id]
            return True
        return False
    
    def list_keys(self) -> List[str]:
        return list(self.key_store.keys())
    
    def rotate_key(self, key_id: str, key_size: int) -> str:
        if key_id in self.key_store:
            return self.generate_key(key_id, key_size)
        return "Key not found"
    
    def encrypt_data(self, key_id: str, data: str) -> str:
        try:
            encoded_key = self.key_store.get(key_id)
            if encoded_key is None:
                return "Key not found"
            
            key = base64.b64decode(encoded_key)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Padding
            pad_length = 16 - (len(data) % 16)
            padded_data = data + (chr(pad_length) * pad_length)
            
            encrypted_data = encryptor.update(padded_data.encode()) + encryptor.finalize()
            result = iv + encrypted_data
            return base64.b64encode(result).decode('utf-8')
        except Exception as e:
            return f"Error: {str(e)}"
    
    def decrypt_data(self, key_id: str, encrypted_data: str) -> str:
        try:
            encoded_key = self.key_store.get(key_id)
            if encoded_key is None:
                return "Key not found"
            
            key = base64.b64decode(encoded_key)
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            pad_length = decrypted_padded[-1]
            decrypted_data = decrypted_padded[:-pad_length]
            
            return decrypted_data.decode('utf-8')
        except Exception as e:
            return f"Error: {str(e)}"


if __name__ == "__main__":
    key_manager = Task134()
    
    print("Test Case 1: Generate and retrieve keys")
    key1 = key_manager.generate_key("key1", 128)
    print(f"Generated key1: {key1}")
    print(f"Retrieved key1: {key_manager.get_key('key1')}")
    print()
    
    print("Test Case 2: List all keys")
    key_manager.generate_key("key2", 256)
    key_manager.generate_key("key3", 128)
    print(f"All keys: {key_manager.list_keys()}")
    print()
    
    print("Test Case 3: Encrypt and decrypt data")
    original_data = "Hello, World!"
    encrypted = key_manager.encrypt_data("key1", original_data)
    print(f"Encrypted: {encrypted}")
    decrypted = key_manager.decrypt_data("key1", encrypted)
    print(f"Decrypted: {decrypted}")
    print()
    
    print("Test Case 4: Rotate key")
    old_key = key_manager.get_key("key2")
    print(f"Old key2: {old_key}")
    new_key = key_manager.rotate_key("key2", 256)
    print(f"New key2: {new_key}")
    print(f"Keys are different: {old_key != new_key}")
    print()
    
    print("Test Case 5: Delete key")
    print(f"Delete key3: {key_manager.delete_key('key3')}")
    print(f"Remaining keys: {key_manager.list_keys()}")
    print(f"Try to get deleted key: {key_manager.get_key('key3')}")
