
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import os
import base64

class Task124:
    def __init__(self):
        self.key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)
        self.encrypted_storage = {}
    
    def encrypt_data(self, plain_text):
        if not plain_text:
            raise ValueError("Data cannot be None or empty")
        
        nonce = os.urandom(12)
        encrypted_data = self.aesgcm.encrypt(nonce, plain_text.encode('utf-8'), None)
        
        encrypted_data_with_nonce = nonce + encrypted_data
        return base64.b64encode(encrypted_data_with_nonce).decode('utf-8')
    
    def decrypt_data(self, encrypted_text):
        if not encrypted_text:
            raise ValueError("Encrypted data cannot be None or empty")
        
        encrypted_data_with_nonce = base64.b64decode(encrypted_text.encode('utf-8'))
        
        nonce = encrypted_data_with_nonce[:12]
        encrypted_data = encrypted_data_with_nonce[12:]
        
        decrypted_data = self.aesgcm.decrypt(nonce, encrypted_data, None)
        return decrypted_data.decode('utf-8')
    
    def store_sensitive_data(self, key, data):
        if not key:
            raise ValueError("Key cannot be None or empty")
        
        encrypted_data = self.encrypt_data(data)
        self.encrypted_storage[key] = encrypted_data
    
    def retrieve_sensitive_data(self, key):
        if not key:
            raise ValueError("Key cannot be None or empty")
        
        encrypted_data = self.encrypted_storage.get(key)
        if encrypted_data is None:
            return None
        
        return self.decrypt_data(encrypted_data)


def main():
    try:
        secure_storage = Task124()
        
        # Test Case 1: Store and retrieve credit card number
        print("Test Case 1: Credit Card Storage")
        secure_storage.store_sensitive_data("creditCard1", "4532-1234-5678-9010")
        retrieved_cc = secure_storage.retrieve_sensitive_data("creditCard1")
        print(f"Retrieved: {retrieved_cc}")
        print()
        
        # Test Case 2: Store and retrieve personal information
        print("Test Case 2: Personal Information")
        secure_storage.store_sensitive_data("ssn1", "123-45-6789")
        retrieved_ssn = secure_storage.retrieve_sensitive_data("ssn1")
        print(f"Retrieved: {retrieved_ssn}")
        print()
        
        # Test Case 3: Store and retrieve email
        print("Test Case 3: Email Storage")
        secure_storage.store_sensitive_data("email1", "user@example.com")
        retrieved_email = secure_storage.retrieve_sensitive_data("email1")
        print(f"Retrieved: {retrieved_email}")
        print()
        
        # Test Case 4: Store and retrieve medical records
        print("Test Case 4: Medical Records")
        secure_storage.store_sensitive_data("medical1", "Patient: John Doe, Condition: Confidential")
        retrieved_medical = secure_storage.retrieve_sensitive_data("medical1")
        print(f"Retrieved: {retrieved_medical}")
        print()
        
        # Test Case 5: Retrieve non-existent data
        print("Test Case 5: Non-existent Key")
        non_existent = secure_storage.retrieve_sensitive_data("nonExistent")
        print(f"Retrieved: {non_existent}")
        
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == "__main__":
    main()
