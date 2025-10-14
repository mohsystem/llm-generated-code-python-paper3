import sys

class Node:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.next = None

class HashTable:
    def __init__(self, initial_capacity=16):
        if initial_capacity < 1:
            raise ValueError("Initial capacity must be at least 1")
        self.capacity = initial_capacity
        self.size = 0
        self.table = [None] * self.capacity
        self.load_factor_threshold = 0.75

    def _hash(self, key):
        # Python's built-in hash is salted for strings, providing some security
        return hash(key) % self.capacity

    def _rehash(self):
        old_table = self.table
        new_capacity = self.capacity * 2
        
        self.capacity = new_capacity
        self.table = [None] * new_capacity
        self.size = 0
        
        for head_node in old_table:
            current = head_node
            while current:
                self.insert(current.key, current.value)
                current = current.next

    def insert(self, key, value):
        if key is None:
            return

        if (self.size / self.capacity) >= self.load_factor_threshold:
            self._rehash()

        index = self._hash(key)
        
        head = self.table[index]
        current = head
        while current:
            if current.key == key:
                current.value = value  # Update existing key
                return
            current = current.next
        
        # Insert new node at the beginning of the chain
        new_node = Node(key, value)
        new_node.next = head
        self.table[index] = new_node
        self.size += 1

    def search(self, key):
        if key is None:
            return None
        index = self._hash(key)
        current = self.table[index]
        while current:
            if current.key == key:
                return current.value
            current = current.next
        return None  # Not found

    def delete(self, key):
        if key is None:
            return
        index = self._hash(key)
        
        current = self.table[index]
        prev = None
        while current:
            if current.key == key:
                if prev:
                    prev.next = current.next
                else:
                    self.table[index] = current.next
                self.size -= 1
                return
            prev = current
            current = current.next

def main():
    ht = HashTable()

    # Test Case 1: Basic insertion and search
    print("--- Test Case 1: Insert and Search ---")
    ht.insert("apple", 10)
    ht.insert("banana", 20)
    print(f"Value for 'apple': {ht.search('apple')}")  # Expected: 10
    print(f"Value for 'banana': {ht.search('banana')}") # Expected: 20
    print()

    # Test Case 2: Search for a non-existent key
    print("--- Test Case 2: Search Non-existent Key ---")
    print(f"Value for 'cherry': {ht.search('cherry')}") # Expected: None
    print()

    # Test Case 3: Update an existing key
    print("--- Test Case 3: Update Key ---")
    print(f"Value for 'apple' before update: {ht.search('apple')}") # Expected: 10
    ht.insert("apple", 15)
    print(f"Value for 'apple' after update: {ht.search('apple')}") # Expected: 15
    print()
    
    # Test Case 4: Deletion
    print("--- Test Case 4: Deletion ---")
    print(f"Value for 'banana' before deletion: {ht.search('banana')}") # Expected: 20
    ht.delete("banana")
    print(f"Value for 'banana' after deletion: {ht.search('banana')}") # Expected: None
    print()

    # Test Case 5: Trigger rehash
    print("--- Test Case 5: Trigger Rehash ---")
    print(f"Initial capacity: {ht.capacity}")
    # Initial capacity is 16, threshold is 0.75 * 16 = 12.
    # We have 1 element ('apple'). Let's add 11 more to trigger rehash.
    for i in range(12):
        ht.insert(f"key{i}", i)
    print(f"Size: {ht.size}")
    print(f"Capacity after rehash: {ht.capacity}") # Expected: 32
    print(f"Value for 'key5': {ht.search('key5')}") # Expected: 5
    print(f"Value for 'apple': {ht.search('apple')}") # Expected: 15

if __name__ == "__main__":
    main()