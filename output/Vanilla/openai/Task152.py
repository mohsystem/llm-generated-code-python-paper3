class Task152:
    class _BucketEntry:
        __slots__ = ("key", "value")
        def __init__(self, key, value):
            self.key = key
            self.value = value

    def __init__(self, capacity=16):
        self.capacity = max(4, capacity)
        self.table = [[] for _ in range(self.capacity)]
        self._size = 0

    def _index(self, key: int) -> int:
        h = hash(key)
        return (h ^ (h >> 16)) & 0x7fffffff % self.capacity

    def insert(self, key: int, value: int) -> None:
        idx = self._index(key)
        bucket = self.table[idx]
        for entry in bucket:
            if entry.key == key:
                entry.value = value
                return
        bucket.append(self._BucketEntry(key, value))
        self._size += 1

    def search(self, key: int):
        idx = self._index(key)
        for entry in self.table[idx]:
            if entry.key == key:
                return entry.value
        return None

    def delete(self, key: int) -> bool:
        idx = self._index(key)
        bucket = self.table[idx]
        for i, entry in enumerate(bucket):
            if entry.key == key:
                bucket.pop(i)
                self._size -= 1
                return True
        return False

    def size(self) -> int:
        return self._size


if __name__ == "__main__":
        ht = Task152(16)

        # Test 1: Insert and search
        ht.insert(1, 10)
        print("Test1 search(1):", ht.search(1))  # 10

        # Test 2: Collision insert and search
        ht.insert(17, 20)  # likely collides with 1 if capacity 16
        print("Test2 search(17):", ht.search(17))  # 20

        # Test 3: Update existing key
        ht.insert(1, 15)
        print("Test3 search(1):", ht.search(1))  # 15

        # Test 4: Delete existing key and verify
        print("Test4 delete(17):", ht.delete(17))  # True
        print("Test4 search(17):", ht.search(17))  # None

        # Test 5: Delete non-existing key and size check
        print("Test5 delete(99):", ht.delete(99))  # False
        print("Test5 size():", ht.size())  # should be 1