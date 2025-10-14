class Node:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.next = None

class HashTable:
    def __init__(self, capacity):
        if capacity <= 0:
            raise ValueError("Capacity must be a positive integer.")
        self.capacity = capacity
        self.buckets = [None] * self.capacity

    def _get_bucket_index(self, key):
        # Ensure index is non-negative
        return abs(hash(key)) % self.capacity

    def search(self, key):
        """Search for a key in the hash table."""
        index = self._get_bucket_index(key)
        current = self.buckets[index]
        while current:
            if current.key == key:
                return current.value
            current = current.next
        return None

    def insert(self, key, value):
        """Insert a key-value pair into the hash table."""
        index = self._get_bucket_index(key)
        current = self.buckets[index]
        # Check if key already exists to update it
        while current:
            if current.key == key:
                current.value = value
                return
            current = current.next
        
        # If key does not exist, insert new node at the beginning of the chain
        new_node = Node(key, value)
        new_node.next = self.buckets[index]
        self.buckets[index] = new_node

    def delete(self, key):
        """Delete a key-value pair from the hash table."""
        index = self._get_bucket_index(key)
        current = self.buckets[index]
        prev = None

        # Traverse the chain to find the key
        while current and current.key != key:
            prev = current
            current = current.next

        # If key is not found
        if not current:
            return

        # If key is found
        if prev:
            prev.next = current.next
        else:
            # The node to delete is the head of the chain
            self.buckets[index] = current.next
        # Python's garbage collector will handle the memory deallocation
        
# Main execution block with test cases
if __name__ == '__main__':
    hash_table = HashTable(10)
    print("Python Hash Table Implementation Test")

    # Test Case 1: Insert key-value pairs. (5 and 15 will collide with capacity 10)
    hash_table.insert(5, 50)
    hash_table.insert(15, 150)
    hash_table.insert(2, 20)
    print("Test 1: Insert (5, 50), (15, 150), (2, 20)")
    print(f"Value for key 15: {hash_table.search(15)}")
    print(f"Value for key 5: {hash_table.search(5)}")
    print(f"Value for key 2: {hash_table.search(2)}")
    print("--------------------")

    # Test Case 2: Search for an existing key.
    print("Test 2: Search for existing key 15")
    print(f"Value: {hash_table.search(15)}")
    print("--------------------")

    # Test Case 3: Search for a non-existing key.
    print("Test 3: Search for non-existing key 25")
    result = hash_table.search(25)
    print(f"Value: {result if result is not None else 'Not Found'}")
    print("--------------------")
    
    # Test Case 4: Update an existing key's value.
    print("Test 4: Update value for key 5 to 55")
    hash_table.insert(5, 55)
    print(f"New value for key 5: {hash_table.search(5)}")
    print("--------------------")

    # Test Case 5: Delete a key and verify deletion.
    print("Test 5: Delete key 15")
    hash_table.delete(15)
    result_deleted = hash_table.search(15)
    print(f"Searching for deleted key 15: {result_deleted if result_deleted is not None else 'Not Found'}")
    result_existing = hash_table.search(5)
    print(f"Searching for key 5 to ensure it's still there: {result_existing}")
    print("--------------------")