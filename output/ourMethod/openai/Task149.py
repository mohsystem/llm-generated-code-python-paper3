from __future__ import annotations
from typing import Tuple

class DequeueResult:
    def __init__(self, success: bool, value: int = 0) -> None:
        self.success = success
        self.value = value

    def __repr__(self) -> str:
        return f"Result{{success={self.success}" + ("" if not self.success else f", value={self.value}") + "}}"

class IntQueue:
    __slots__ = ("_buf", "_capacity", "_head", "_tail", "_size")
    MAX_CAPACITY = 1_000_000

    def __init__(self, capacity: int) -> None:
        if not isinstance(capacity, int):
            raise TypeError("capacity must be an int")
        if capacity < 1 or capacity > self.MAX_CAPACITY:
            raise ValueError(f"Capacity must be between 1 and {self.MAX_CAPACITY}")
        self._capacity = capacity
        self._buf = [0] * capacity
        self._head = 0
        self._tail = 0
        self._size = 0

    def size(self) -> int:
        return self._size

    def capacity(self) -> int:
        return self._capacity

    def is_empty(self) -> bool:
        return self._size == 0

    def is_full(self) -> bool:
        return self._size == self._capacity

    def enqueue(self, value: int) -> bool:
        if not isinstance(value, int):
            return False
        if self.is_full():
            return False
        self._buf[self._tail] = value
        self._tail = (self._tail + 1) % self._capacity
        self._size += 1
        return True

    def dequeue(self) -> DequeueResult:
        if self.is_empty():
            return DequeueResult(False, 0)
        v = self._buf[self._head]
        self._head = (self._head + 1) % self._capacity
        self._size -= 1
        return DequeueResult(True, v)

    def peek(self) -> DequeueResult:
        if self.is_empty():
            return DequeueResult(False, 0)
        return DequeueResult(True, self._buf[self._head])

    def __repr__(self) -> str:
        items = []
        for i in range(self._size):
            idx = (self._head + i) % self._capacity
            items.append(str(self._buf[idx]))
        return f"IntQueue(size={self._size}, capacity={self._capacity}, data=[{', '.join(items)}])"

def test1() -> None:
    print("TEST 1: Basic enqueue/dequeue")
    q = IntQueue(3)
    print("enqueue 1 ->", q.enqueue(1))
    print("enqueue 2 ->", q.enqueue(2))
    print("enqueue 3 ->", q.enqueue(3))
    print("queue:", q)
    print("peek ->", q.peek())
    print("dequeue ->", q.dequeue())
    print("dequeue ->", q.dequeue())
    print("dequeue ->", q.dequeue())
    print("dequeue (empty) ->", q.dequeue())
    print("queue:", q)

def test2() -> None:
    print("TEST 2: Overflow handling")
    q = IntQueue(2)
    print("enqueue 10 ->", q.enqueue(10))
    print("enqueue 20 ->", q.enqueue(20))
    print("enqueue 30 (should fail) ->", q.enqueue(30))
    print("peek ->", q.peek())
    print("queue:", q)

def test3() -> None:
    print("TEST 3: Peek on empty")
    q = IntQueue(5)
    print("peek (empty) ->", q.peek())
    print("enqueue 7 ->", q.enqueue(7))
    print("peek ->", q.peek())
    print("dequeue ->", q.dequeue())
    print("peek (empty) ->", q.peek())

def test4() -> None:
    print("TEST 4: Wrap-around behavior")
    q = IntQueue(3)
    print("enqueue 1 ->", q.enqueue(1))
    print("enqueue 2 ->", q.enqueue(2))
    print("dequeue ->", q.dequeue())
    print("enqueue 3 ->", q.enqueue(3))
    print("enqueue 4 ->", q.enqueue(4))
    print("is_full ->", q.is_full())
    print("queue:", q)
    print("dequeue ->", q.dequeue())
    print("dequeue ->", q.dequeue())
    print("dequeue ->", q.dequeue())
    print("is_empty ->", q.is_empty())

def test5() -> None:
    print("TEST 5: Capacity 1 edge case")
    q = IntQueue(1)
    print("enqueue 42 ->", q.enqueue(42))
    print("enqueue 99 (should fail) ->", q.enqueue(99))
    print("peek ->", q.peek())
    print("dequeue ->", q.dequeue())
    print("dequeue (empty) ->", q.dequeue())

if __name__ == "__main__":
    try:
        test1()
        print()
        test2()
        print()
        test3()
        print()
        test4()
        print()
        test5()
    except Exception as ex:
        print("Error:", str(ex))