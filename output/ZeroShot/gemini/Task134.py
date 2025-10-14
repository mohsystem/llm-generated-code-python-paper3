import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# NOTE: This code requires the 'cryptography' library.
# Install it using: pip install cryptography

class KeyManager:
    """
    Manages cryptographic keys securely in memory.
    This is a simplified example. In a real-world application:
    - The master key should not be derived from a hardcoded password.
    - The master key should be protected by a Hardware Security Module (HSM).
    """
    _KDF_ITERATIONS = 65536
    _KEY_SIZE_BYTES = 32  # 256-bit master key
    _AES_NONCE_BYTES = 12 # 96 bits for GCM

    def __init__(self, password: str, salt: bytes):
        """
        Initializes the KeyManager, deriving a master key from the password.
        """
        if not isinstance(password, str) or not password:
            raise ValueError("Password must be a non-empty string.")
        if not isinstance(salt, bytes) or len(salt) < 16:
            raise ValueError("Salt must be at least 16 bytes.")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self._KEY_SIZE_BYTES,
            salt=salt,
            iterations=self._KDF_ITERATIONS,
            backend=default_backend()
        )
        self._master_key = kdf.derive(password.encode('utf-8'))
        self._key_store = {}

    def generate_key(self, alias: str, key_size_bytes: int = 32) -> bool:
        """
        Generates a new random key, encrypts it, and stores it under an alias.
        
        :param alias: The name to associate with the key.
        :param key_size_bytes: The size of the key to generate in bytes (e.g., 16, 32).
        :return: True if successful, False otherwise.
        """
        try:
            if not isinstance(alias, str) or not alias:
                raise ValueError("Alias must be a non-empty string.")

            new_key = os.urandom(key_size_bytes)
            
            # Encrypt (wrap) the new key with the master key using AES-GCM
            aesgcm = AESGCM(self._master_key)
            nonce = os.urandom(self._AES_NONCE_BYTES)
            wrapped_key = aesgcm.encrypt(nonce, new_key, None) # No associated data

            self._key_store[alias] = {'nonce': nonce, 'wrapped_key': wrapped_key}

            # Securely clear the plaintext key from memory (best effort in Python)
            del new_key

            return True
        except Exception as e:
            print(f"Error generating key for alias '{alias}': {e}")
            return False

    def get_key(self, alias: str) -> bytes | None:
        """
        Retrieves and decrypts a stored key.
        
        :param alias: The name of the key to retrieve.
        :return: The plaintext key as bytes, or None if not found or decryption fails.
        """
        stored_entry = self._key_store.get(alias)
        if not stored_entry:
            return None

        try:
            aesgcm = AESGCM(self._master_key)
            nonce = stored_entry['nonce']
            wrapped_key = stored_entry['wrapped_key']
            
            # The returned key is a copy, caller should handle it securely.
            unwrapped_key = aesgcm.decrypt(nonce, wrapped_key, None)
            return unwrapped_key
        except InvalidTag:
            print(f"Error: Key for alias '{alias}' seems to be tampered with. Decryption failed.")
            return None
        except Exception as e:
            print(f"Error retrieving key for alias '{alias}': {e}")
            return None
    
    def delete_key(self, alias: str) -> bool:
        """
        Deletes a key from the key store.
        
        :param alias: The name of the key to delete.
        :return: True if the key existed and was deleted, False otherwise.
        """
        if alias in self._key_store:
            del self._key_store[alias]
            return True
        return False

def main():
    """Main function with test cases."""
    print("--- Python KeyManager Tests ---")
    try:
        # In a real application, the password would be obtained securely,
        # and the salt would be unique and stored.
        master_password = "a-very-strong-master-password"
        salt = b'\x1a\x2b\x3c\x4d\x5e\x6f\x7a\x8b\x11\x22\x33\x44\x55\x66\x77\x88'
        
        key_manager = KeyManager(master_password, salt)

        # Test Case 1: Generate a new key
        print("1. Generating key 'api-key-1'...")
        generated = key_manager.generate_key("api-key-1", 32)
        print(f"   Key generated: {generated}")
        assert generated

        # Test Case 2: Retrieve the key
        print("\n2. Retrieving key 'api-key-1'...")
        key1 = key_manager.get_key("api-key-1")
        print(f"   Key retrieved: {key1 is not None}")
        if key1:
            print(f"   Key length (bytes): {len(key1)}")
        assert key1 is not None

        # Test Case 3: Generate a second key
        print("\n3. Generating key 'db-key-2'...")
        generated2 = key_manager.generate_key("db-key-2", 16)
        print(f"   Key generated: {generated2}")
        key2 = key_manager.get_key("db-key-2")
        print(f"   Second key retrieved: {key2 is not None}")
        assert generated2 and key2 is not None

        # Test Case 4: Delete the first key
        print("\n4. Deleting key 'api-key-1'...")
        deleted = key_manager.delete_key("api-key-1")
        print(f"   Key deleted: {deleted}")
        assert deleted

        # Test Case 5: Attempt to retrieve the deleted key
        print("\n5. Attempting to retrieve deleted key 'api-key-1'...")
        deleted_key = key_manager.get_key("api-key-1")
        print(f"   Key retrieved: {deleted_key is not None}")
        assert deleted_key is None
        
        print("\nAll tests passed.")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()