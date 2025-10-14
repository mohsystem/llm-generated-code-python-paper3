class Queue:
    def __init__(self, initial_capacity=16):
        if initial_capacity <= 0:
            raise ValueError("Initial capacity must be positive.")
        self._data = [0] * initial_capacity
        self._head = 0
        self._tail = 0
        self._size = 0

    def _ensure_capacity_for_one_more(self):
        if self._size < len(self._data):
            return
        current = len(self._data)
        proposed = current * 2
        max_cap = 1 << 30
        if proposed > max_cap:
            if current == max_cap:
                raise MemoryError("Queue too large.")
            proposed = max_cap
        new_data = [0] * proposed
        if self._head <= self._tail:
            new_data[0:self._size] = self._data[self._head:self._tail]
        else:
            first_part = len(self._data) - self._head
            new_data[0:first_part] = self._data[self._head:]
            new_data[first_part:first_part + self._tail] = self._data[0:self._tail]
        self._data = new_data
        self._head = 0
        self._tail = self._size

    def enqueue(self, value: int) -> bool:
        self._ensure_capacity_for_one_more()
        self._data[self._tail] = value
        self._tail = (self._tail + 1) % len(self._data)
        self._size += 1
        return True

    def dequeue(self):
        if self._size == 0:
            return None
        val = self._data[self._head]
        self._data[self._head] = 0
        self._head = (self._head + 1) % len(self._data)
        self._size -= 1
        return val

    def peek(self):
        if self._size == 0:
            return None
        return self._data[self._head]

    def size(self) -> int:
        return self._size

    def is_empty(self) -> bool:
        return self._size == 0


def main():
    q = Queue()

    # Test 1
    q.enqueue(1)
    q.enqueue(2)
    q.enqueue(3)
    print("Test1 Peek:", q.peek())  # expect 1
    print("Test1 Dequeue:", q.dequeue())  # expect 1

    # Test 2
    print("Test2 Dequeue:", q.dequeue())  # expect 2
    print("Test2 Dequeue:", q.dequeue())  # expect 3
    print("Test2 Dequeue Empty:", q.dequeue())  # expect None

    # Test 3
    q.enqueue(10)
    print("Test3 Peek:", q.peek())  # expect 10
    q.enqueue(20)
    print("Test3 Dequeue:", q.dequeue())  # expect 10
    print("Test3 Peek:", q.peek())  # expect 20

    # Test 4
    for i in range(100):
        q.enqueue(i)
    print("Test4 Size after 100 enqueues:", q.size())  # expect >= 101
    print("Test4 Peek:", q.peek())  # expect 20
    for _ in range(5):
        print("Test4 Dequeue:", q.dequeue())

    # Test 5
    q2 = Queue()
    print("Test5 IsEmpty:", q2.is_empty())  # expect True
    print("Test5 Peek Empty:", q2.peek())  # expect None
    q2.enqueue(99)
    print("Test5 Dequeue:", q2.dequeue())  # expect 99
    print("Test5 Dequeue Empty:", q2.dequeue())  # expect None


if __name__ == "__main__":
    main()