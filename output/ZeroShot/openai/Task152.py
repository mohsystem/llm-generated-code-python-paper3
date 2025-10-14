import secrets

class HashTable:
    _DEFAULT_CAPACITY = 16
    _LOAD_FACTOR = 0.75

    def __init__(self, capacity: int = _DEFAULT_CAPACITY):
        if capacity <= 0:
            capacity = self._DEFAULT_CAPACITY
        capacity = self._next_power_of_two(capacity)
        self._buckets = [[] for _ in range(capacity)]
        self._size = 0
        self._threshold = int(capacity * self._LOAD_FACTOR)
        self._salt = int.from_bytes(secrets.token_bytes(8), 'big', signed=False)

    def _next_power_of_two(self, n: int) -> int:
        c = 1
        while c < n:
            c <<= 1
        return c

    def _fnv1a64(self, data: bytes) -> int:
        hash_ = 0xcbf29ce484222325  # 14695981039346656037
        prime = 0x100000001b3       # 1099511628211
        for b in data:
            hash_ ^= b
            hash_ = (hash_ * prime) & 0xFFFFFFFFFFFFFFFF
        return hash_

    def _index(self, key: str) -> int:
        h = self._fnv1a64(key.encode('utf-8')) ^ self._salt
        return h & (len(self._buckets) - 1)

    def _resize_if_needed(self) -> None:
        if self._size <= self._threshold:
            return
        new_cap = len(self._buckets) << 1
        new_buckets = [[] for _ in range(new_cap)]
        mask = new_cap - 1
        for bucket in self._buckets:
            for k, v in bucket:
                h = (self._fnv1a64(k.encode('utf-8')) ^ self._salt) & mask
                new_buckets[h].append([k, v])
        self._buckets = new_buckets
        self._threshold = int(new_cap * self._LOAD_FACTOR)

    # Inserts or updates. Returns True if new insert, False if updated.
    def put(self, key: str, value: int) -> bool:
        if key is None:
            raise ValueError("key must not be None")
        idx = self._index(key)
        bucket = self._buckets[idx]
        for pair in bucket:
            if pair[0] == key:
                pair[1] = value
                return False
        bucket.append([key, value])
        self._size += 1
        self._resize_if_needed()
        return True

    # Deletes key. Returns True if deleted, False if not found.
    def delete(self, key: str) -> bool:
        if key is None:
            raise ValueError("key must not be None")
        idx = self._index(key)
        bucket = self._buckets[idx]
        for i, pair in enumerate(bucket):
            if pair[0] == key:
                del bucket[i]
                self._size -= 1
                return True
        return False

    # Returns value if present, else None.
    def get(self, key: str):
        if key is None:
            raise ValueError("key must not be None")
        idx = self._index(key)
        bucket = self._buckets[idx]
        for k, v in bucket:
            if k == key:
                return v
        return None

    def size(self) -> int:
        return self._size


def main():
    ht = HashTable()

    # Test case 1: insert and search
    ht.put("apple", 1)
    ht.put("banana", 2)
    ht.put("cherry", 3)
    print("T1 banana=", ht.get("banana"))  # expect 2

    # Test case 2: update existing
    ht.put("banana", 20)
    print("T2 banana=", ht.get("banana"))  # expect 20

    # Test case 3: delete and search
    deleted = ht.delete("apple")
    print("T3 apple_deleted=", deleted, " val=", ht.get("apple"))  # expect True, None

    # Test case 4: search non-existent
    print("T4 durian=", ht.get("durian"))  # expect None

    # Test case 5: insert more and verify
    ht.put("elderberry", 5)
    ht.put("fig", 6)
    print("T5 elderberry=", ht.get("elderberry"), " size=", ht.size())  # expect 5 and size


if __name__ == "__main__":
    main()