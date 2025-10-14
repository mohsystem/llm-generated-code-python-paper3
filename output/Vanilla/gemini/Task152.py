class HashNode:
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.next = None

class HashTable:
    def __init__(self, capacity):
        self.capacity = capacity
        self.table = [None] * self.capacity

    def _hash_function(self, key):
        return abs(hash(key)) % self.capacity

    def insert(self, key, value):
        index = self._hash_function(key)
        head = self.table[index]
        
        # Check if key already exists and update
        current = head
        while current:
            if current.key == key:
                current.value = value
                return
            current = current.next

        # Key not found, insert at the beginning of the chain
        new_node = HashNode(key, value)
        new_node.next = head
        self.table[index] = new_node

    def search(self, key):
        index = self._hash_function(key)
        head = self.table[index]
        
        # Traverse the chain
        current = head
        while current:
            if current.key == key:
                return current.value
            current = current.next
        
        # Key not found
        return None

    def delete(self, key):
        index = self._hash_function(key)
        head = self.table[index]
        prev = None
        current = head
        
        # Find the node with the key
        while current:
            if current.key == key:
                break
            prev = current
            current = current.next
        
        # If key was not found
        if not current:
            return

        # Unlink the node
        if prev:
            prev.next = current.next
        else:
            # It's the head of the chain
            self.table[index] = current.next
            
    def display(self):
        print("---- HASH TABLE ----")
        for i in range(self.capacity):
            print(f"Index {i}:", end="")
            current = self.table[i]
            while current:
                print(f" -> ({current.key}, {current.value})", end="")
                current = current.next
            print()
        print("--------------------")

# Main function with test cases
def main():
    hash_table = HashTable(10)

    print("----- Testing Insert and Search -----")
    hash_table.insert(1, 10)
    hash_table.insert(2, 20)
    hash_table.insert(12, 120)  # Collision with key 2
    hash_table.display()

    print(f"\nSearch for key 2: {hash_table.search(2)}")
    print(f"Search for key 12: {hash_table.search(12)}")
    print(f"Search for key 5 (non-existent): {hash_table.search(5)}")

    print("\n----- Testing Update -----")
    hash_table.insert(2, 22)  # Update value for key 2
    print(f"Search for key 2 after update: {hash_table.search(2)}")
    hash_table.display()

    print("\n----- Testing Delete -----")
    hash_table.delete(12)
    print(f"Search for key 12 after delete: {hash_table.search(12)}")
    print(f"Search for key 2 after deleting 12: {hash_table.search(2)}")
    hash_table.display()
    
    print("\n----- More Test Cases -----")
    hash_table.insert(22, 220) # Another collision at index 2
    hash_table.insert(32, 320) # Another collision at index 2
    hash_table.display()
    print("Deleting head of a chain (key 32)...")
    hash_table.delete(32)
    hash_table.display()
    print(f"Search for 32: {hash_table.search(32)}")
    print(f"Search for 22: {hash_table.search(22)}")

if __name__ == "__main__":
    main()