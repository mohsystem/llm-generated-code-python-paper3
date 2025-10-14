
from typing import Optional, List

class Entry:
    def __init__(self, key: str, value: str):
        if key is None:
            raise ValueError("Key cannot be None")
        self.key: str = key
        self.value: str = value
        self.next: Optional[Entry] = None


class HashTable:
    DEFAULT_CAPACITY: int = 16
    LOAD_FACTOR: float = 0.75
    MAX_CAPACITY: int = 1 << 30

    def __init__(self):
        self.capacity: int = HashTable.DEFAULT_CAPACITY
        self.table: List[Optional[Entry]] = [None] * self.capacity
        self.size: int = 0

    def _hash(self, key: str) -> int:
        if key is None:
            raise ValueError("Key cannot be None")
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        
        hash_value: int = 0
        key_bytes: bytes = key.encode('utf-8')
        for byte in key_bytes:
            hash_value = (31 * hash_value + byte) & 0x7FFFFFFF
        return hash_value % self.capacity

    def insert(self, key: str, value: str) -> None:
        if key is None:
            raise ValueError("Key cannot be None")
        if value is None:
            raise ValueError("Value cannot be None")
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        if not isinstance(value, str):
            raise TypeError("Value must be a string")
        if len(key) > 1000:
            raise ValueError("Key too long")

        if self.size >= self.capacity * HashTable.LOAD_FACTOR:
            self._resize()

        index: int = self._hash(key)
        current: Optional[Entry] = self.table[index]

        while current is not None:
            if current.key == key:
                current.value = value
                return
            current = current.next

        new_entry: Entry = Entry(key, value)
        new_entry.next = self.table[index]
        self.table[index] = new_entry
        self.size += 1

    def search(self, key: str) -> Optional[str]:
        if key is None:
            raise ValueError("Key cannot be None")
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        if len(key) > 1000:
            raise ValueError("Key too long")

        index: int = self._hash(key)
        current: Optional[Entry] = self.table[index]

        while current is not None:
            if current.key == key:
                return current.value
            current = current.next

        return None

    def delete(self, key: str) -> bool:
        if key is None:
            raise ValueError("Key cannot be None")
        if not isinstance(key, str):
            raise TypeError("Key must be a string")
        if len(key) > 1000:
            raise ValueError("Key too long")

        index: int = self._hash(key)
        current: Optional[Entry] = self.table[index]
        prev: Optional[Entry] = None

        while current is not None:
            if current.key == key:
                if prev is None:
                    self.table[index] = current.next
                else:
                    prev.next = current.next
                self.size -= 1
                return True
            prev = current
            current = current.next

        return False

    def _resize(self) -> None:
        if self.capacity >= HashTable.MAX_CAPACITY:
            return

        new_capacity: int = self.capacity * 2
        if new_capacity < 0 or new_capacity > HashTable.MAX_CAPACITY:
            new_capacity = HashTable.MAX_CAPACITY

        old_table: List[Optional[Entry]] = self.table
        old_capacity: int = self.capacity
        self.capacity = new_capacity
        self.table = [None] * self.capacity
        self.size = 0

        for i in range(old_capacity):
            current: Optional[Entry] = old_table[i]
            while current is not None:
                self.insert(current.key, current.value)
                current = current.next

    def get_size(self) -> int:
        return self.size


def main() -> None:
    hash_table = HashTable()

    print("Test 1: Insert and search")
    hash_table.insert("name", "Alice")
    hash_table.insert("age", "30")
    print(f"name: {hash_table.search('name')}")
    print(f"age: {hash_table.search('age')}")

    print("\\nTest 2: Update existing key")
    hash_table.insert("name", "Bob")
    print(f"name after update: {hash_table.search('name')}")

    print("\\nTest 3: Delete operation")
    deleted = hash_table.delete("age")
    print(f"Deleted age: {deleted}")
    print(f"age after delete: {hash_table.search('age')}")

    print("\\nTest 4: Search non-existent key")
    print(f"non-existent: {hash_table.search('non-existent')}")

    print("\\nTest 5: Multiple operations")
    hash_table.insert("city", "NYC")
    hash_table.insert("country", "USA")
    hash_table.insert("zip", "10001")
    print(f"Size: {hash_table.get_size()}")
    print(f"city: {hash_table.search('city')}")
    hash_table.delete("country")
    print(f"Size after delete: {hash_table.get_size()}")


if __name__ == "__main__":
    main()
