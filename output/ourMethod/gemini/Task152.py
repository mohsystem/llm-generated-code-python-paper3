from typing import Optional, Any

class Node:
    def __init__(self, key: Any, value: Any):
        self.key = key
        self.value = value
        self.next: Optional[Node] = None

class HashTable:
    def __init__(self, capacity: int):
        if capacity <= 0:
            raise ValueError("Capacity must be positive.")
        self.capacity = capacity
        self.table: list[Optional[Node]] = [None] * self.capacity

    def _hash(self, key: Any) -> int:
        # Use Python's built-in hash and ensure non-negative index
        return abs(hash(key)) % self.capacity

    def insert(self, key: Any, value: Any) -> None:
        index = self._hash(key)
        head = self.table[index]
        
        # Search for the key. If it exists, update the value.
        current = head
        while current:
            if current.key == key:
                current.value = value
                return
            current = current.next
            
        # If key not found, insert a new node at the beginning of the chain.
        new_node = Node(key, value)
        new_node.next = head
        self.table[index] = new_node

    def search(self, key: Any) -> Optional[Any]:
        index = self._hash(key)
        current = self.table[index]
        
        while current:
            if current.key == key:
                return current.value
            current = current.next
            
        return None # Key not found

    def delete(self, key: Any) -> None:
        index = self._hash(key)
        current = self.table[index]
        prev = None

        while current:
            if current.key == key:
                if prev:
                    # Node is in the middle or at the end
                    prev.next = current.next
                else:
                    # Node to be deleted is the head of the chain
                    self.table[index] = current.next
                return # Key found and deleted
            prev = current
            current = current.next
            
    def print_table(self) -> None:
        print("---- Hash Table ----")
        for i, node in enumerate(self.table):
            print(f"Bucket {i}: ", end="")
            if not node:
                print("[]")
                continue
            current = node
            while current:
                print(f"[K:{current.key}, V:{current.value}] -> ", end="")
                current = current.next
            print("None")
        print("--------------------")

if __name__ == "__main__":
    ht = HashTable(10)

    # Test Case 1: Insert new key-value pairs
    print("Test Case 1: Inserting new elements")
    ht.insert(1, 10)
    ht.insert(11, 110)  # Should collide with key 1 if capacity is 10
    ht.insert(2, 20)
    ht.insert(12, 120)
    ht.print_table()

    # Test Case 2: Search for an existing key
    print("\nTest Case 2: Searching for key 11")
    value = ht.search(11)
    print(f"Value for key 11: {value if value is not None else 'Not Found'}")

    # Test Case 3: Search for a non-existing key
    print("\nTest Case 3: Searching for key 99")
    value = ht.search(99)
    print(f"Value for key 99: {value if value is not None else 'Not Found'}")

    # Test Case 4: Update an existing key
    print("\nTest Case 4: Updating key 1 to value 100")
    print(f"Value for key 1 before update: {ht.search(1)}")
    ht.insert(1, 100)
    print(f"Value for key 1 after update: {ht.search(1)}")
    ht.print_table()

    # Test Case 5: Delete a key and verify
    print("\nTest Case 5: Deleting key 11")
    ht.delete(11)
    print("Searching for key 11 after deletion...")
    value = ht.search(11)
    print(f"Value for key 11: {value if value is not None else 'Not Found'}")
    ht.print_table()