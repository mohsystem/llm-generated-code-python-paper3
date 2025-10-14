from typing import List, Optional, Tuple


class HashTable:
    def __init__(self, capacity: int = 17) -> None:
        if capacity <= 0:
            raise ValueError("Capacity must be positive")
        self._cap: int = capacity
        self._buckets: List[List[Tuple[int, int]]] = [[] for _ in range(capacity)]

    def _index(self, key: int) -> int:
        h = (key * 0x9E3779B1) & 0xFFFFFFFF
        h ^= (h >> 16)
        return abs(h) % self._cap

    # Inserts key->value. Returns True if inserted new, False if updated.
    def insert(self, key: int, value: int) -> bool:
        idx = self._index(key)
        bucket = self._buckets[idx]
        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (k, value)
                return False
        bucket.append((key, value))
        return True

    # Deletes key. Returns True if existed and removed, False otherwise.
    def delete(self, key: int) -> bool:
        idx = self._index(key)
        bucket = self._buckets[idx]
        for i, (k, _) in enumerate(bucket):
            if k == key:
                del bucket[i]
                return True
        return False

    # Searches key. Returns value if found, else None.
    def search(self, key: int) -> Optional[int]:
        idx = self._index(key)
        bucket = self._buckets[idx]
        for k, v in bucket:
            if k == key:
                return v
        return None


def main() -> None:
    ht = HashTable(17)

    # Test 1: Insert and search basic
    t1_insert = ht.insert(1, 100) and ht.insert(2, 200) and ht.insert(3, 300)
    t1_search = (ht.search(1) == 100 and ht.search(2) == 200 and ht.search(3) == 300)
    print(f"Test1 Insert new keys: {t1_insert}")
    print(f"Test1 Search keys: {t1_search}")

    # Test 2: Update existing key
    updated = not ht.insert(2, 250)
    v2 = ht.search(2)
    print(f"Test2 Update existing: {updated and v2 == 250}")

    # Test 3: Delete existing key
    del3 = ht.delete(3)
    notFound3 = ht.search(3) is None
    print(f"Test3 Delete existing: {del3 and notFound3}")

    # Test 4: Delete non-existing key
    del99 = ht.delete(99)
    print(f"Test4 Delete non-existing: {not del99}")

    # Test 5: Search non-existing key after sequence
    searchNF = ht.search(42) is None
    print(f"Test5 Search non-existing: {searchNF}")


if __name__ == "__main__":
    main()