
class Task152:
    def __init__(self, size=10):
        self.TABLE_SIZE = size
        self.table = [[] for _ in range(self.TABLE_SIZE)]
    
    def _hash(self, key):
        if key is None:
            return 0
        hash_value = 0
        for char in str(key):
            hash_value = (hash_value * 31 + ord(char)) % self.TABLE_SIZE
        return abs(hash_value)
    
    def insert(self, key, value):
        if key is None:
            print("Error: Key cannot be None")
            return
        
        index = self._hash(key)
        bucket = self.table[index]
        
        # Update if key exists
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return
        
        # Insert new entry
        bucket.append((key, value))
    
    def search(self, key):
        if key is None:
            print("Error: Key cannot be None")
            return None
        
        index = self._hash(key)
        bucket = self.table[index]
        
        for k, v in bucket:
            if k == key:
                return v
        
        return None
    
    def delete(self, key):
        if key is None:
            print("Error: Key cannot be None")
            return False
        
        index = self._hash(key)
        bucket = self.table[index]
        
        for i, (k, v) in enumerate(bucket):
            if k == key:
                del bucket[i]
                return True
        
        return False


def main():
    hash_table = Task152()
    
    # Test Case 1: Insert and search
    print("Test 1: Insert and Search")
    hash_table.insert("apple", 100)
    hash_table.insert("banana", 200)
    print(f"Search 'apple': {hash_table.search('apple')}")
    print(f"Search 'banana': {hash_table.search('banana')}")
    
    # Test Case 2: Update existing key
    print("\\nTest 2: Update Existing Key")
    hash_table.insert("apple", 150)
    print(f"Search 'apple' after update: {hash_table.search('apple')}")
    
    # Test Case 3: Delete operation
    print("\\nTest 3: Delete Operation")
    print(f"Delete 'banana': {hash_table.delete('banana')}")
    print(f"Search 'banana' after delete: {hash_table.search('banana')}")
    
    # Test Case 4: Search non-existent key
    print("\\nTest 4: Search Non-existent Key")
    print(f"Search 'orange': {hash_table.search('orange')}")
    
    # Test Case 5: None key handling
    print("\\nTest 5: None Key Handling")
    hash_table.insert(None, 300)
    print(f"Search None: {hash_table.search(None)}")
    print(f"Delete None: {hash_table.delete(None)}")


if __name__ == "__main__":
    main()
