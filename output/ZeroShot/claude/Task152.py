
class HashNode:
    def __init__(self, key, value):
        self.key = key
        self.value = value

class HashTable:
    def __init__(self, capacity=10):
        self.capacity = capacity
        self.size = 0
        self.buckets = [[] for _ in range(capacity)]
    
    def _get_bucket_index(self, key):
        hash_code = hash(key)
        return abs(hash_code) % self.capacity
    
    def insert(self, key, value):
        bucket_index = self._get_bucket_index(key)
        bucket = self.buckets[bucket_index]
        
        for node in bucket:
            if node.key == key:
                node.value = value
                return
        
        bucket.append(HashNode(key, value))
        self.size += 1
    
    def search(self, key):
        bucket_index = self._get_bucket_index(key)
        bucket = self.buckets[bucket_index]
        
        for node in bucket:
            if node.key == key:
                return node.value
        
        return None
    
    def delete(self, key):
        bucket_index = self._get_bucket_index(key)
        bucket = self.buckets[bucket_index]
        
        for i, node in enumerate(bucket):
            if node.key == key:
                bucket.pop(i)
                self.size -= 1
                return True
        
        return False
    
    def get_size(self):
        return self.size
    
    def is_empty(self):
        return self.size == 0

def main():
    print("Test Case 1: Basic Insert and Search")
    ht1 = HashTable(10)
    ht1.insert("apple", 5)
    ht1.insert("banana", 10)
    ht1.insert("orange", 15)
    print(f"Search 'apple': {ht1.search('apple')}")
    print(f"Search 'banana': {ht1.search('banana')}")
    print(f"Size: {ht1.get_size()}")
    
    print("\\nTest Case 2: Delete Operation")
    ht2 = HashTable(10)
    ht2.insert("key1", 100)
    ht2.insert("key2", 200)
    print(f"Before delete - Size: {ht2.get_size()}")
    print(f"Delete 'key1': {ht2.delete('key1')}")
    print(f"After delete - Size: {ht2.get_size()}")
    print(f"Search 'key1': {ht2.search('key1')}")
    
    print("\\nTest Case 3: Update Existing Key")
    ht3 = HashTable(10)
    ht3.insert("counter", 1)
    print(f"Initial value: {ht3.search('counter')}")
    ht3.insert("counter", 2)
    print(f"Updated value: {ht3.search('counter')}")
    print(f"Size: {ht3.get_size()}")
    
    print("\\nTest Case 4: Search Non-existent Key")
    ht4 = HashTable(10)
    ht4.insert("exists", 99)
    print(f"Search 'exists': {ht4.search('exists')}")
    print(f"Search 'notexists': {ht4.search('notexists')}")
    
    print("\\nTest Case 5: Multiple Operations")
    ht5 = HashTable(10)
    ht5.insert(1, "one")
    ht5.insert(2, "two")
    ht5.insert(3, "three")
    print(f"Search 2: {ht5.search(2)}")
    ht5.delete(2)
    print(f"After delete 2: {ht5.search(2)}")
    ht5.insert(4, "four")
    print(f"Search 4: {ht5.search(4)}")
    print(f"Final size: {ht5.get_size()}")

if __name__ == "__main__":
    main()
