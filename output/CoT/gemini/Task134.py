import os
import base64

# NOTE: This is a demonstration of cryptographic key management concepts.
# Storing raw key material in application memory is NOT a secure practice
# for production systems. Production systems should use Hardware Security
# Modules (HSMs) or dedicated key management services (e.g., AWS KMS, Azure Key Vault).

class KeyManager:
    """A simple in-memory class to manage cryptographic keys."""
    def __init__(self):
        self._key_store = {}

    def generate_key(self, key_name: str, key_size_in_bytes: int) -> bool:
        """
        Generates a new key using a cryptographically secure RNG.
        :param key_name: The alias to store the key under.
        :param key_size_in_bytes: The size of the key in bytes (e.g., 16, 24, 32 for AES).
        :return: True if successful, False otherwise.
        """
        if not key_name:
            print("Error: Key name cannot be empty.")
            return False
        if key_size_in_bytes not in [16, 24, 32]:
            print(f"Warning: Generating key of non-standard size {key_size_in_bytes} bytes.")

        # os.urandom is suitable for cryptographic use
        key_material = os.urandom(key_size_in_bytes)
        self._key_store[key_name] = bytearray(key_material) # Use bytearray to allow modification
        return True

    def get_key(self, key_name: str) -> bytes | None:
        """
        Retrieves a copy of the key material for the given key name.
        :param key_name: The alias of the key to retrieve.
        :return: A copy of the key as bytes, or None if not found.
        """
        key_material = self._key_store.get(key_name)
        if key_material:
            # Return an immutable copy
            return bytes(key_material)
        return None

    def delete_key(self, key_name: str) -> bool:
        """
        Deletes a key from the store and overwrites its memory.
        :param key_name: The alias of the key to delete.
        :return: True if the key was found and deleted, False otherwise.
        """
        if key_name in self._key_store:
            # Overwrite the key material for security before deleting
            key_material = self._key_store[key_name]
            for i in range(len(key_material)):
                key_material[i] = 0
            del self._key_store[key_name]
            return True
        return False

    def list_keys(self) -> list[str]:
        """Lists all key names currently in the store."""
        return list(self._key_store.keys())

def main():
    """Main function with test cases."""
    key_manager = KeyManager()
    print("--- Python Key Manager Test ---")

    # Test Case 1: Generate a new key
    print("\n1. Generating a 32-byte (256-bit) key named 'api_key_1'...")
    generated = key_manager.generate_key("api_key_1", 32)
    print(f"Key generated successfully: {generated}")
    print(f"Current keys: {key_manager.list_keys()}")

    # Test Case 2: Retrieve the key
    print("\n2. Retrieving key 'api_key_1'...")
    retrieved_key = key_manager.get_key("api_key_1")
    if retrieved_key:
        print(f"Retrieved key (Base64): {base64.b64encode(retrieved_key).decode('utf-8')}")
        print(f"Retrieved key length: {len(retrieved_key) * 8} bits")
    else:
        print("Failed to retrieve key.")

    # Test Case 3: Attempt to retrieve a non-existent key
    print("\n3. Attempting to retrieve non-existent key 'fake_key'...")
    fake_key = key_manager.get_key("fake_key")
    print(f"Retrieved 'fake_key': {'null (as expected)' if fake_key is None else 'FAIL'}")

    # Test Case 4: Delete the key
    print("\n4. Deleting key 'api_key_1'...")
    deleted = key_manager.delete_key("api_key_1")
    print(f"Key deleted successfully: {deleted}")
    print(f"Current keys: {key_manager.list_keys()}")

    # Test Case 5: Attempt to retrieve the deleted key
    print("\n5. Attempting to retrieve deleted key 'api_key_1'...")
    deleted_key = key_manager.get_key("api_key_1")
    print(f"Retrieved 'api_key_1' after deletion: {'null (as expected)' if deleted_key is None else 'FAIL'}")

if __name__ == "__main__":
    main()