
class HashNode:
    def __init__(self, key, value):
        self.key = key
        self.value = value

class Task152:
    def __init__(self, capacity=10):
        self.capacity = capacity
        self.size = 0
        self.table = [[] for _ in range(capacity)]
    
    def hash(self, key):
        return hash(key) % self.capacity
    
    def insert(self, key, value):
        index = self.hash(key)
        bucket = self.table[index]
        
        for node in bucket:
            if node.key == key:
                node.value = value
                return
        
        bucket.append(HashNode(key, value))
        self.size += 1
    
    def search(self, key):
        index = self.hash(key)
        bucket = self.table[index]
        
        for node in bucket:
            if node.key == key:
                return node.value
        
        return None
    
    def delete(self, key):
        index = self.hash(key)
        bucket = self.table[index]
        
        for i, node in enumerate(bucket):
            if node.key == key:
                bucket.pop(i)
                self.size -= 1
                return True
        
        return False
    
    def get_size(self):
        return self.size

if __name__ == "__main__":
    print("Test Case 1: Basic insert and search")
    ht1 = Task152(10)
    ht1.insert("apple", 100)
    ht1.insert("banana", 200)
    ht1.insert("orange", 300)
    print(f"Search 'apple': {ht1.search('apple')}")
    print(f"Search 'banana': {ht1.search('banana')}")
    print(f"Search 'orange': {ht1.search('orange')}")
    
    print("\\nTest Case 2: Delete operation")
    ht2 = Task152(10)
    ht2.insert("cat", 50)
    ht2.insert("dog", 60)
    print(f"Before delete - Search 'cat': {ht2.search('cat')}")
    ht2.delete("cat")
    print(f"After delete - Search 'cat': {ht2.search('cat')}")
    print(f"Search 'dog': {ht2.search('dog')}")
    
    print("\\nTest Case 3: Update existing key")
    ht3 = Task152(10)
    ht3.insert("key1", 10)
    print(f"Initial value: {ht3.search('key1')}")
    ht3.insert("key1", 20)
    print(f"Updated value: {ht3.search('key1')}")
    
    print("\\nTest Case 4: Search non-existent key")
    ht4 = Task152(10)
    ht4.insert("exist", 100)
    print(f"Search 'exist': {ht4.search('exist')}")
    print(f"Search 'notexist': {ht4.search('notexist')}")
    
    print("\\nTest Case 5: Multiple operations")
    ht5 = Task152(10)
    ht5.insert("a", 1)
    ht5.insert("b", 2)
    ht5.insert("c", 3)
    print(f"Size: {ht5.get_size()}")
    ht5.delete("b")
    print(f"After delete, Size: {ht5.get_size()}")
    print(f"Search 'a': {ht5.search('a')}")
    print(f"Search 'b': {ht5.search('b')}")
    print(f"Search 'c': {ht5.search('c')}")
