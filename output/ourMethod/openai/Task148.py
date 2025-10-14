from typing import Optional


class IntStack:
    def __init__(self, capacity: int):
        if not isinstance(capacity, int) or capacity <= 0 or capacity > 1_000_000:
            raise ValueError("Invalid capacity")
        self._data: list[int] = [0] * capacity
        self._top: int = 0

    def push(self, value: int) -> bool:
        if not isinstance(value, int):
            return False
        if self._top >= len(self._data):
            return False
        self._data[self._top] = value
        self._top += 1
        return True

    def pop(self) -> Optional[int]:
        if self._top == 0:
            return None
        self._top -= 1
        return self._data[self._top]

    def peek(self) -> Optional[int]:
        if self._top == 0:
            return None
        return self._data[self._top - 1]

    def size(self) -> int:
        return self._top

    def is_empty(self) -> bool:
        return self._top == 0

    def capacity(self) -> int:
        return len(self._data)


def main() -> None:
    # Test 1: Basic push/pop/peek
    s1 = IntStack(3)
    print("T1 push 10:", s1.push(10))
    print("T1 push 20:", s1.push(20))
    print("T1 peek:", s1.peek())
    print("T1 pop:", s1.pop())
    print("T1 pop:", s1.pop())
    print("T1 pop empty:", s1.pop())

    # Test 2: Overflow behavior
    s2 = IntStack(1)
    print("T2 push 5:", s2.push(5))
    print("T2 push 6 overflow:", s2.push(6))
    print("T2 peek:", s2.peek())
    print("T2 size:", s2.size())

    # Test 3: Empty stack operations
    s3 = IntStack(2)
    print("T3 empty peek:", s3.peek())
    print("T3 empty pop:", s3.pop())
    print("T3 isEmpty:", s3.is_empty())

    # Test 4: Fill and partial pop
    s4 = IntStack(4)
    print("T4 push 1:", s4.push(1))
    print("T4 push 2:", s4.push(2))
    print("T4 push 3:", s4.push(3))
    print("T4 size:", s4.size())
    print("T4 pop:", s4.pop())
    print("T4 peek:", s4.peek())

    # Test 5: Mixed operations
    s5 = IntStack(5)
    print("T5 push 7:", s5.push(7))
    print("T5 push 8:", s5.push(8))
    print("T5 push 9:", s5.push(9))
    print("T5 peek:", s5.peek())
    print("T5 pop:", s5.pop())
    print("T5 push 10:", s5.push(10))
    print("T5 size:", s5.size())


if __name__ == "__main__":
    main()