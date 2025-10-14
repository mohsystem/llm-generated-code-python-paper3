class Task149:
    class Node:
        __slots__ = ("value", "next")
        def __init__(self, value):
            self.value = value
            self.next = None

    class SafeQueue:
        def __init__(self):
            self._head = None
            self._tail = None
            self._size = 0

        # Enqueue: returns True on success, False if value is None or size overflow (simulated)
        def enqueue(self, value):
            if value is None:
                return False
            # Python int doesn't overflow, but keep a defensive upper bound
            max_size = (1 << 63) - 1
            if self._size >= max_size:
                return False
            node = Task149.Node(value)
            if self._tail is None:
                self._head = self._tail = node
            else:
                self._tail.next = node
                self._tail = node
            self._size += 1
            return True

        # Dequeue: returns value or None if empty
        def dequeue(self):
            if self._head is None:
                return None
            val = self._head.value
            old = self._head
            self._head = self._head.next
            old.next = None
            if self._head is None:
                self._tail = None
            self._size -= 1
            return val

        # Peek: returns value or None if empty
        def peek(self):
            return None if self._head is None else self._head.value

        def is_empty(self):
            return self._head is None

        def size(self):
            return self._size


def main():
    # Test 1
    q1 = Task149.SafeQueue()
    q1.enqueue(1)
    q1.enqueue(2)
    q1.enqueue(3)
    print("Test1 Peek (expect 1):", q1.peek())
    print("Test1 Dequeue (expect 1):", q1.dequeue())
    print("Test1 Peek (expect 2):", q1.peek())
    print("Test1 Size (expect 2):", q1.size())

    # Test 2
    q2 = Task149.SafeQueue()
    print("Test2 Dequeue empty (expect None):", q2.dequeue())
    print("Test2 Peek empty (expect None):", q2.peek())
    print("Test2 Size (expect 0):", q2.size())

    # Test 3
    q3 = Task149.SafeQueue()
    q3.enqueue(10)
    print("Test3 Dequeue (expect 10):", q3.dequeue())
    q3.enqueue(20)
    q3.enqueue(30)
    print("Test3 Peek (expect 20):", q3.peek())
    print("Test3 Size (expect 2):", q3.size())

    # Test 4
    q4 = Task149.SafeQueue()
    q4.enqueue(-5)
    q4.enqueue(0)
    print("Test4 Dequeue (expect -5):", q4.dequeue())
    print("Test4 Peek (expect 0):", q4.peek())
    print("Test4 Size (expect 1):", q4.size())

    # Test 5
    q5 = Task149.SafeQueue()
    for i in range(100, 105):
        q5.enqueue(i)
    print("Test5 Dequeue1 (expect 100):", q5.dequeue())
    print("Test5 Dequeue2 (expect 101):", q5.dequeue())
    print("Test5 Dequeue3 (expect 102):", q5.dequeue())
    print("Test5 Peek (expect 103):", q5.peek())
    print("Test5 Size (expect 2):", q5.size())


if __name__ == "__main__":
    main()