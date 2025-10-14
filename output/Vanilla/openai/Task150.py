class Node:
    def __init__(self, val: int):
        self.val = val
        self.next = None


class SinglyLinkedList:
    def __init__(self):
        self.head = None

    # Insert at the end
    def insert(self, value: int) -> None:
        if self.head is None:
            self.head = Node(value)
            return
        cur = self.head
        while cur.next is not None:
            cur = cur.next
        cur.next = Node(value)

    # Delete first occurrence of value
    def delete(self, value: int) -> bool:
        cur = self.head
        prev = None
        while cur is not None:
            if cur.val == value:
                if prev is None:
                    self.head = cur.next
                else:
                    prev.next = cur.next
                return True
            prev = cur
            cur = cur.next
        return False

    # Search for a value
    def search(self, value: int) -> bool:
        cur = self.head
        while cur is not None:
            if cur.val == value:
                return True
            cur = cur.next
        return False

    def to_list(self):
        res = []
        cur = self.head
        while cur is not None:
            res.append(cur.val)
            cur = cur.next
        return res

    def __str__(self):
        return "[" + ", ".join(str(x) for x in self.to_list()) + "]"


def run_tests():
    # Test 1: Insert sequence
    lst = SinglyLinkedList()
    lst.insert(10)
    lst.insert(20)
    lst.insert(30)
    print("Test1 list after inserts:", lst)

    # Test 2: Search existing
    print("Test2 search 20:", lst.search(20))

    # Test 3: Delete middle
    print("Test3 delete 20:", lst.delete(20), ", list:", lst)

    # Test 4: Delete head and tail
    print("Test4 delete 10:", lst.delete(10), ", delete 30:", lst.delete(30), ", list:", lst)

    # Test 5: Delete on empty and search non-existing
    print("Test5 delete 99 on empty:", lst.delete(99), ", search 99:", lst.search(99))


if __name__ == "__main__":
    run_tests()