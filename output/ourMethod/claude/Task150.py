
from typing import Optional


class Node:
    def __init__(self, value: int) -> None:
        self._value: int = value
        self._next: Optional[Node] = None

    @property
    def value(self) -> int:
        return self._value

    @property
    def next(self) -> Optional['Node']:
        return self._next

    @next.setter
    def next(self, node: Optional['Node']) -> None:
        self._next = node


class SinglyLinkedList:
    MAX_SIZE: int = 100000

    def __init__(self) -> None:
        self._head: Optional[Node] = None
        self._size: int = 0

    def insert(self, value: int) -> bool:
        if not isinstance(value, int):
            return False
        if self._size >= self.MAX_SIZE:
            return False
        try:
            new_node = Node(value)
            if self._head is None:
                self._head = new_node
            else:
                current = self._head
                while current.next is not None:
                    current = current.next
                current.next = new_node
            self._size += 1
            return True
        except MemoryError:
            return False

    def delete(self, value: int) -> bool:
        if not isinstance(value, int):
            return False
        if self._head is None:
            return False

        if self._head.value == value:
            self._head = self._head.next
            self._size -= 1
            return True

        current = self._head
        while current.next is not None:
            if current.next.value == value:
                current.next = current.next.next
                self._size -= 1
                return True
            current = current.next
        return False

    def search(self, value: int) -> bool:
        if not isinstance(value, int):
            return False
        current = self._head
        while current is not None:
            if current.value == value:
                return True
            current = current.next
        return False

    def get_size(self) -> int:
        return self._size


def main() -> None:
    try:
        # Test case 1: Basic insert and search
        list1 = SinglyLinkedList()
        list1.insert(10)
        list1.insert(20)
        list1.insert(30)
        print(f"Test 1 - Search 20: {list1.search(20)}")
        print(f"Test 1 - Search 40: {list1.search(40)}")

        # Test case 2: Delete operation
        list2 = SinglyLinkedList()
        list2.insert(5)
        list2.insert(15)
        list2.insert(25)
        print(f"Test 2 - Delete 15: {list2.delete(15)}")
        print(f"Test 2 - Search 15: {list2.search(15)}")

        # Test case 3: Delete head
        list3 = SinglyLinkedList()
        list3.insert(100)
        list3.insert(200)
        print(f"Test 3 - Delete 100: {list3.delete(100)}")
        print(f"Test 3 - Search 100: {list3.search(100)}")

        # Test case 4: Empty list operations
        list4 = SinglyLinkedList()
        print(f"Test 4 - Search in empty: {list4.search(50)}")
        print(f"Test 4 - Delete from empty: {list4.delete(50)}")

        # Test case 5: Multiple operations
        list5 = SinglyLinkedList()
        list5.insert(1)
        list5.insert(2)
        list5.insert(3)
        list5.delete(2)
        list5.insert(4)
        print(f"Test 5 - Search 2: {list5.search(2)}")
        print(f"Test 5 - Search 4: {list5.search(4)}")
        print(f"Test 5 - Size: {list5.get_size()}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
