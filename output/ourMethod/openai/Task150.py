from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, Tuple

@dataclass
class _Node:
    value: int
    next: Optional["_Node"] = None

class SinglyLinkedList:
    def __init__(self) -> None:
        self._head: Optional[_Node] = None
        self._size: int = 0

    def size(self) -> int:
        return self._size

    def insert_at_head(self, value: int) -> bool:
        node = _Node(value=value, next=self._head)
        self._head = node
        self._size += 1
        return True

    def insert_at_tail(self, value: int) -> bool:
        node = _Node(value=value)
        if self._head is None:
            self._head = node
            self._size = 1
            return True
        cur = self._head
        while cur.next is not None:
            cur = cur.next
        cur.next = node
        self._size += 1
        return True

    def insert_at_index(self, index: int, value: int) -> bool:
        if index < 0 or index > self._size:
            return False
        if index == 0:
            return self.insert_at_head(value)
        prev = self._head
        for _ in range(index - 1):
            assert prev is not None
            prev = prev.next
        node = _Node(value=value, next=prev.next if prev else None)
        assert prev is not None
        prev.next = node
        self._size += 1
        return True

    def delete_value(self, value: int) -> bool:
        prev: Optional[_Node] = None
        cur = self._head
        while cur is not None and cur.value != value:
            prev = cur
            cur = cur.next
        if cur is None:
            return False
        if prev is None:
            self._head = cur.next
        else:
            prev.next = cur.next
        self._size -= 1
        return True

    def delete_at_index(self, index: int) -> Optional[int]:
        if index < 0 or index >= self._size:
            return None
        prev: Optional[_Node] = None
        cur = self._head
        for _ in range(index):
            prev = cur
            assert cur is not None
            cur = cur.next
        assert cur is not None
        val = cur.value
        if prev is None:
            self._head = cur.next
        else:
            prev.next = cur.next
        self._size -= 1
        return val

    def search(self, value: int) -> int:
        idx = 0
        cur = self._head
        while cur is not None:
            if cur.value == value:
                return idx
            idx += 1
            cur = cur.next
        return -1

    def to_list(self) -> List[int]:
        out: List[int] = []
        cur = self._head
        while cur is not None:
            out.append(cur.value)
            cur = cur.next
        return out

    def __str__(self) -> str:
        return str(self.to_list())

def main() -> None:
    lst = SinglyLinkedList()

    # Test 1
    lst.insert_at_tail(1)
    lst.insert_at_tail(2)
    lst.insert_at_tail(3)
    print("Test1 list:", lst)
    print("Test1 search(2):", lst.search(2))
    print("Test1 delete_value(2):", lst.delete_value(2), "=>", lst, "search(2):", lst.search(2))

    # Test 2
    print("Test2 insert_at_head(10):", lst.insert_at_head(10), "=>", lst)

    # Test 3
    print("Test3 insert_at_index(1,99):", lst.insert_at_index(1, 99), "=>", lst)
    print("Test3 insert_at_index(size+2,5):", lst.insert_at_index(lst.size() + 2, 5), "=>", lst)

    # Test 4
    print("Test4 delete_at_index(0):", lst.delete_at_index(0), "=>", lst)
    print("Test4 delete_at_index(size):", lst.delete_at_index(lst.size()), "=>", lst)

    # Test 5
    print("Test5 search(100):", lst.search(100))

if __name__ == "__main__":
    main()