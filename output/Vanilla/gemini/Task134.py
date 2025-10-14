import os

class KeyManager:
    """A simple class to manage cryptographic keys in memory."""

    def __init__(self, key_size_bytes=32):
        """Initializes the KeyManager."""
        self._key_store = {}
        self.key_size_bytes = key_size_bytes

    def generate_key(self, key_id: str) -> str:
        """
        Generates a new cryptographic key and stores it with the given ID.
        :param key_id: The identifier for the key.
        :return: The generated key as a hex string.
        """
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("Key ID must be a non-empty string.")
        
        key = os.urandom(self.key_size_bytes)
        self._key_store[key_id] = key
        return key.hex()

    def get_key(self, key_id: str) -> bytes | None:
        """
        Retrieves a key by its ID.
        :param key_id: The identifier for the key.
        :return: The key as bytes, or None if not found.
        """
        return self._key_store.get(key_id)

    def delete_key(self, key_id: str) -> bool:
        """
        Deletes a key by its ID.
        :param key_id: The identifier for the key.
        :return: True if the key was deleted, False otherwise.
        """
        if key_id in self._key_store:
            del self._key_store[key_id]
            return True
        return False

    def list_keys(self) -> list[str]:
        """
        Lists all key identifiers currently in the store.
        :return: A list of all key IDs.
        """
        return list(self._key_store.keys())

def main():
    """Main function with test cases."""
    key_manager = KeyManager()
    print("Cryptographic Key Manager - Python")
    print("---------------------------------")

    # Test Case 1: Generate a key for "user1"
    print("1. Generating key for 'user1'...")
    key1_hex = key_manager.generate_key("user1")
    print(f"   Generated key for 'user1': {key1_hex}")
    print()

    # Test Case 2: Generate a key for "user2"
    print("2. Generating key for 'user2'...")
    key2_hex = key_manager.generate_key("user2")
    print(f"   Generated key for 'user2': {key2_hex}")
    print()

    # Test Case 3: Retrieve and print the key for "user1"
    print("3. Retrieving key for 'user1'...")
    retrieved_key1 = key_manager.get_key("user1")
    print(f"   Retrieved key for 'user1': {retrieved_key1.hex() if retrieved_key1 else 'Not Found'}")
    print()

    # Test Case 4: Attempt to retrieve a key for "user3" (non-existent)
    print("4. Attempting to retrieve non-existent key 'user3'...")
    retrieved_key3 = key_manager.get_key("user3")
    print(f"   Retrieved key for 'user3': {'Not Found' if retrieved_key3 is None else retrieved_key3.hex()}")
    print()

    # Test Case 5: Delete the key for "user2" and list remaining keys
    print("5. Deleting key for 'user2' and listing keys...")
    deleted = key_manager.delete_key("user2")
    print(f"   Key 'user2' deleted: {deleted}")
    print(f"   Current keys in store: {key_manager.list_keys()}")
    print("---------------------------------")


if __name__ == "__main__":
    main()