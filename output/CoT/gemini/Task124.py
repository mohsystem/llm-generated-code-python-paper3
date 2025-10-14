import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class SecureDataStore:
    """
    A secure in-memory data store for sensitive information.
    This class encrypts data using AES-GCM with a key derived from a password using PBKDF2.
    WARNING: This is an example for demonstration purposes. Real-world secure storage
    requires careful key management, platform-specific protections, and threat modeling.
    Do not hardcode passwords in production applications.
    """
    # Cryptographic parameters
    _SALT_SIZE = 16  # bytes
    _NONCE_SIZE = 12 # bytes for AES-GCM
    _KEY_SIZE = 32   # bytes (256 bits)
    _PBKDF2_ITERATIONS = 65536 # OWASP recommendation

    def __init__(self):
        # In-memory vault to store encrypted data. Key is an identifier, Value is a Base64 encoded
        # string containing: salt + nonce + ciphertext.
        self._vault = {}
        self._backend = default_backend()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a secret key from a password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self._KEY_SIZE,
            salt=salt,
            iterations=self._PBKDF2_ITERATIONS,
            backend=self._backend
        )
        return kdf.derive(password.encode('utf-8'))

    def store_data(self, id: str, data: str, password: str):
        """Encrypts and stores a piece of sensitive data."""
        try:
            # 1. Generate a random salt for key derivation.
            salt = os.urandom(self._SALT_SIZE)
            
            # 2. Derive a strong encryption key from the password and salt.
            key = self._derive_key(password, salt)
            
            # 3. Encrypt the data using AES-GCM.
            aesgcm = AESGCM(key)
            
            # 4. Generate a random nonce (IV). It must be unique for each encryption with the same key.
            nonce = os.urandom(self._NONCE_SIZE)
            
            # 5. Perform encryption.
            ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
            
            # 6. Combine salt, nonce, and ciphertext, then Base64 encode for storage.
            combined = salt + nonce + ciphertext
            self._vault[id] = base64.b64encode(combined).decode('utf-8')

        except Exception as e:
            # In a real application, use a robust logging framework and specific exceptions.
            raise RuntimeError(f"Could not store data: {e}")

    def retrieve_data(self, id: str, password: str) -> str | None:
        """
        Retrieves and decrypts a piece of sensitive data.
        Returns the decrypted data, or None if decryption fails (e.g., wrong password).
        """
        encrypted_data_b64 = self._vault.get(id)
        if not encrypted_data_b64:
            return None
        
        try:
            combined = base64.b64decode(encrypted_data_b64)
            
            # 1. Extract salt, nonce, and ciphertext from the stored data.
            salt = combined[:self._SALT_SIZE]
            nonce = combined[self._SALT_SIZE:self._SALT_SIZE + self._NONCE_SIZE]
            ciphertext = combined[self._SALT_SIZE + self._NONCE_SIZE:]
            
            # 2. Re-derive the key using the same password and the extracted salt.
            key = self._derive_key(password, salt)
            
            # 3. Decrypt the data. AES-GCM automatically handles integrity checking.
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')

        except Exception:
            # An exception (e.g., InvalidTag) means a wrong password or tampered data.
            # Do not expose detailed error messages.
            return None


def main():
    """Main function with test cases."""
    store = SecureDataStore()
    master_password = "aVery!Strong_Password123"

    print("--- Test Case 1: Storing multiple sensitive data entries ---")
    store.store_data("CreditCard_1", "1111-2222-3333-4444", master_password)
    store.store_data("SSN_PersonA", "987-65-4321", master_password)
    store.store_data("Email_Password", "S3cr3tP@ssw0rd!", master_password)
    store.store_data("API_Key_Prod", "xyz-abc-def-ghi-jkl-mno", master_password)
    store.store_data("MedicalRecord_ID", "MRN-555-01-1234", master_password)
    print("5 entries stored successfully.\n")

    print("--- Test Case 2: Retrieving one entry with the correct password ---")
    credit_card = store.retrieve_data("CreditCard_1", master_password)
    print(f"Retrieved Credit Card: {credit_card}")
    assert credit_card == "1111-2222-3333-4444"
    print()

    print("--- Test Case 3: Attempting to retrieve an entry with the WRONG password ---")
    failed_retrieval = store.retrieve_data("SSN_PersonA", "wrongPassword")
    print(f"Result of retrieval with wrong password: {failed_retrieval}")
    assert failed_retrieval is None
    print("As expected, retrieval failed (returned None).\n")
    
    print("--- Test Case 4: Attempting to retrieve a non-existent entry ---")
    non_existent = store.retrieve_data("NonExistentKey", master_password)
    print(f"Result of retrieving non-existent key: {non_existent}")
    assert non_existent is None
    print("As expected, retrieval failed (returned None).\n")
    
    print("--- Test Case 5: Retrieving all stored entries successfully ---")
    print(f"API Key: {store.retrieve_data('API_Key_Prod', master_password)}")
    print(f"Email Password: {store.retrieve_data('Email_Password', master_password)}")
    print(f"SSN: {store.retrieve_data('SSN_PersonA', master_password)}")
    print(f"Medical Record: {store.retrieve_data('MedicalRecord_ID', master_password)}")
    print("All tests completed.")

if __name__ == "__main__":
    main()