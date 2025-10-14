
import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Dict, Set, Optional
import base64

class Task134:
    AES_KEY_SIZE = 32  # 256 bits
    RSA_KEY_SIZE = 2048
    GCM_IV_LENGTH = 12
    GCM_TAG_LENGTH = 16
    PBKDF2_ITERATIONS = 100000
    
    def __init__(self, master_password: str):
        self.key_store: Dict[str, bytes] = {}
        self.master_key = self._derive_master_key(master_password.encode('utf-8'))
    
    def _derive_master_key(self, password: bytes) -> bytes:
        salt = secrets.token_bytes(32)
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=self.AES_KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def generate_aes_key(self, key_id: str) -> str:
        if not key_id or not key_id.strip():
            raise ValueError("Key ID cannot be null or empty")
        
        key = secrets.token_bytes(self.AES_KEY_SIZE)
        encrypted_key = self._encrypt_key(key)
        self.key_store[key_id] = encrypted_key
        
        return key_id
    
    def generate_rsa_key_pair(self, key_id: str) -> str:
        if not key_id or not key_id.strip():
            raise ValueError("Key ID cannot be null or empty")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        encrypted_private = self._encrypt_key(private_bytes)
        encrypted_public = self._encrypt_key(public_bytes)
        
        self.key_store[f"{key_id}_private"] = encrypted_private
        self.key_store[f"{key_id}_public"] = encrypted_public
        
        return key_id
    
    def _encrypt_key(self, key_bytes: bytes) -> bytes:
        iv = secrets.token_bytes(self.GCM_IV_LENGTH)
        
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        encrypted_key = encryptor.update(key_bytes) + encryptor.finalize()
        
        return iv + encrypted_key + encryptor.tag
    
    def _decrypt_key(self, encrypted_data: bytes) -> bytes:
        iv = encrypted_data[:self.GCM_IV_LENGTH]
        tag = encrypted_data[-self.GCM_TAG_LENGTH:]
        encrypted_key = encrypted_data[self.GCM_IV_LENGTH:-self.GCM_TAG_LENGTH]
        
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_key) + decryptor.finalize()
    
    def delete_key(self, key_id: str) -> bool:
        if key_id is None:
            return False
        return self.key_store.pop(key_id, None) is not None
    
    def key_exists(self, key_id: str) -> bool:
        return key_id is not None and key_id in self.key_store
    
    def list_keys(self) -> Set[str]:
        return set(self.key_store.keys())
    
    def clear_all_keys(self):
        self.key_store.clear()


def main():
    try:
        # Test Case 1: Initialize key manager
        print("Test Case 1: Initialize Key Manager")
        key_manager = Task134("SecurePassword123!@#")
        print("Key manager initialized successfully")
        print()
        
        # Test Case 2: Generate AES keys
        print("Test Case 2: Generate AES Keys")
        aes_key1 = key_manager.generate_aes_key("aes-key-001")
        aes_key2 = key_manager.generate_aes_key("aes-key-002")
        print(f"Generated AES keys: {aes_key1}, {aes_key2}")
        print(f"Key exists (aes-key-001): {key_manager.key_exists('aes-key-001')}")
        print()
        
        # Test Case 3: Generate RSA key pairs
        print("Test Case 3: Generate RSA Key Pairs")
        rsa_key1 = key_manager.generate_rsa_key_pair("rsa-keypair-001")
        print(f"Generated RSA key pair: {rsa_key1}")
        print(f"Private key exists: {key_manager.key_exists('rsa-keypair-001_private')}")
        print(f"Public key exists: {key_manager.key_exists('rsa-keypair-001_public')}")
        print()
        
        # Test Case 4: List all keys
        print("Test Case 4: List All Keys")
        all_keys = key_manager.list_keys()
        print(f"Total keys stored: {len(all_keys)}")
        print(f"Keys: {all_keys}")
        print()
        
        # Test Case 5: Delete keys
        print("Test Case 5: Delete Keys")
        deleted = key_manager.delete_key("aes-key-001")
        print(f"Deleted aes-key-001: {deleted}")
        print(f"Key exists after deletion: {key_manager.key_exists('aes-key-001')}")
        print(f"Remaining keys: {len(key_manager.list_keys())}")
        
        key_manager.clear_all_keys()
        print(f"All keys cleared. Remaining keys: {len(key_manager.list_keys())}")
        
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()
