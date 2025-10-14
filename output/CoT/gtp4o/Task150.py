# Chain-of-Through process in code generation:
# 1) Problem understanding: Implement singly linked list with insert, delete, and search operations.
# 2) Security requirements: Validate indices and handle empty-list cases gracefully.
# 3) Secure coding generation: Defensive checks and no reliance on external input.
# 4) Code review: Checked null handling and size updates.
# 5) Secure code output: Final code is robust with 5 tests.

class Node:
    __slots__ = ("val", "next")
    def __init__(self, val, nxt=None):
        self.val = val
        self.next = nxt

class SinglyLinkedList:
    def __init__(self):
        self.head = None
        self._size = 0

    def size(self):
        return self._size

    def insert_at_head(self, value: int) -> None:
        self.head = Node(value, self.head)
        self._size += 1

    def insert_at_tail(self, value: int) -> None:
        n = Node(value)
        if self.head is None:
            self.head = n
        else:
            cur = self.head
            while cur.next is not None:
                cur = cur.next
            cur.next = n
        self._size += 1

    def insert_at_index(self, index: int, value: int) -> bool:
        if index < 0 or index > self._size:
            return False
        if index == 0:
            self.insert_at_head(value)
            return True
        prev = self.head
        for _ in range(index - 1):
            if prev is None:
                return False
            prev = prev.next
        n = Node(value, prev.next)
        prev.next = n
        self._size += 1
        return True

    def delete_by_value(self, value: int) -> bool:
        prev = None
        cur = self.head
        while cur is not None and cur.val != value:
            prev = cur
            cur = cur.next
        if cur is None:
            return False
        if prev is None:
            self.head = cur.next
        else:
            prev.next = cur.next
        self._size -= 1
        return True

    def delete_at_index(self, index: int) -> bool:
        if index < 0 or index >= self._size:
            return False
        if index == 0:
            if self.head is not None:
                self.head = self.head.next
                self._size -= 1
                return True
            return False
        prev = self.head
        for _ in range(index - 1):
            if prev is None:
                return False
            prev = prev.next
        if prev is None or prev.next is None:
            return False
        prev.next = prev.next.next
        self._size -= 1
        return True

    def index_of(self, value: int) -> int:
        idx = 0
        cur = self.head
        while cur is not None:
            if cur.val == value:
                return idx
            cur = cur.next
            idx += 1
        return -1

    def __str__(self) -> str:
        vals = []
        cur = self.head
        while cur is not None:
            vals.append(str(cur.val))
            cur = cur.next
        return "[" + " -> ".join(vals) + "]"

def main():
    # 5 Test cases
    lst = SinglyLinkedList()

    # Test 1: Insert at head and tail
    lst.insert_at_head(3)
    lst.insert_at_tail(5)
    lst.insert_at_tail(7)
    print("Test1:", str(lst), "| size=", lst.size())

    # Test 2: Insert at index
    print("Test2: insert_at_index(1,4) =", lst.insert_at_index(1, 4), "->", lst, "| size=", lst.size())

    # Test 3: Search
    print("Test3: index_of(5) =", lst.index_of(5), ", index_of(9) =", lst.index_of(9))

    # Test 4: Delete by value
    print("Test4: delete_by_value(4) =", lst.delete_by_value(4), ", delete_by_value(42) =", lst.delete_by_value(42), "->", lst, "| size=", lst.size())

    # Test 5: Delete at index
    print("Test5: delete_at_index(1) =", lst.delete_at_index(1), "->", lst, "| size=", lst.size())

if __name__ == "__main__":
    main()