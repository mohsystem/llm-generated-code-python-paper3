class Node:
    __slots__ = ("val", "next")
    def __init__(self, val: int) -> None:
        self.val = val
        self.next = None

class SinglyLinkedList:
    def __init__(self) -> None:
        self.head = None  # type: Node | None
        self.tail = None  # type: Node | None
        self._size = 0

    def insert(self, value: int) -> bool:
        n = Node(value)
        if self.head is None:
            self.head = n
            self.tail = n
        else:
            assert self.tail is not None
            self.tail.next = n
            self.tail = n
        self._size += 1
        return True

    def delete(self, value: int) -> bool:
        prev = None
        curr = self.head
        while curr is not None:
            if curr.val == value:
                if prev is None:
                    self.head = curr.next
                else:
                    prev.next = curr.next
                if curr is self.tail:
                    self.tail = prev
                curr.next = None
                self._size -= 1
                return True
            prev = curr
            curr = curr.next
        return False

    def search(self, value: int) -> bool:
        curr = self.head
        while curr is not None:
            if curr.val == value:
                return True
            curr = curr.next
        return False

    def size(self) -> int:
        return self._size

    def to_list(self) -> list[int]:
        out: list[int] = []
        curr = self.head
        while curr is not None:
            out.append(curr.val)
            curr = curr.next
        return out

def main() -> None:
    # Test Case 1
    lst1 = SinglyLinkedList()
    lst1.insert(1); lst1.insert(2); lst1.insert(3)
    print("TC1 search 2:", lst1.search(2))
    print("TC1 delete 2:", lst1.delete(2))
    print("TC1 search 2:", lst1.search(2))
    print("TC1 list:", lst1.to_list())

    # Test Case 2: delete head
    lst2 = SinglyLinkedList()
    lst2.insert(10); lst2.insert(20)
    print("TC2 delete 10:", lst2.delete(10))
    print("TC2 list:", lst2.to_list())

    # Test Case 3: delete tail
    lst3 = SinglyLinkedList()
    lst3.insert(7); lst3.insert(8); lst3.insert(9)
    print("TC3 delete 9:", lst3.delete(9))
    print("TC3 list:", lst3.to_list())

    # Test Case 4: delete non-existent
    lst4 = SinglyLinkedList()
    lst4.insert(5)
    print("TC4 delete 6:", lst4.delete(6))
    print("TC4 list:", lst4.to_list())

    # Test Case 5: search in empty
    lst5 = SinglyLinkedList()
    print("TC5 search 42:", lst5.search(42))
    print("TC5 list:", lst5.to_list())

if __name__ == "__main__":
    main()