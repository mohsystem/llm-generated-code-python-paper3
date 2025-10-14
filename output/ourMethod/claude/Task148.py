
from typing import TypeVar, Generic, List, Optional

T = TypeVar('T')

class Stack(Generic[T]):
    def __init__(self, capacity: int = 100000):
        if not isinstance(capacity, int) or capacity <= 0 or capacity > 100000:
            raise ValueError("Capacity must be an integer between 1 and 100000")
        self._items: List[T] = []
        self._max_capacity: int = capacity
    
    def push(self, item: T) -> None:
        if item is None:
            raise ValueError("Cannot push None item")
        if len(self._items) >= self._max_capacity:
            raise OverflowError("Stack overflow: capacity exceeded")
        self._items.append(item)
    
    def pop(self) -> T:
        if not self._items:
            raise IndexError("Stack underflow: cannot pop from empty stack")
        return self._items.pop()
    
    def peek(self) -> T:
        if not self._items:
            raise IndexError("Stack is empty: cannot peek")
        return self._items[-1]
    
    def is_empty(self) -> bool:
        return len(self._items) == 0
    
    def size(self) -> int:
        return len(self._items)


def main() -> None:
    # Test case 1: Basic push, peek, and pop operations
    print("Test 1: Basic operations")
    stack1: Stack[int] = Stack(10)
    stack1.push(10)
    stack1.push(20)
    stack1.push(30)
    print(f"Peek: {stack1.peek()}")
    print(f"Pop: {stack1.pop()}")
    print(f"Pop: {stack1.pop()}")
    print(f"Size: {stack1.size()}")
    print()
    
    # Test case 2: String stack
    print("Test 2: String stack")
    stack2: Stack[str] = Stack(5)
    stack2.push("Hello")
    stack2.push("World")
    print(f"Peek: {stack2.peek()}")
    print(f"Pop: {stack2.pop()}")
    print(f"Peek: {stack2.peek()}")
    print()
    
    # Test case 3: Empty stack operations
    print("Test 3: Empty stack check")
    stack3: Stack[float] = Stack(10)
    print(f"Is empty: {stack3.is_empty()}")
    stack3.push(3.14)
    print(f"Is empty: {stack3.is_empty()}")
    stack3.pop()
    print(f"Is empty after pop: {stack3.is_empty()}")
    print()
    
    # Test case 4: Capacity limit
    print("Test 4: Capacity limit")
    stack4: Stack[int] = Stack(3)
    stack4.push(1)
    stack4.push(2)
    stack4.push(3)
    try:
        stack4.push(4)
    except OverflowError as e:
        print(f"Caught overflow: {e}")
    print()
    
    # Test case 5: Exception handling for underflow
    print("Test 5: Underflow handling")
    stack5: Stack[int] = Stack(10)
    stack5.push(100)
    stack5.pop()
    try:
        stack5.pop()
    except IndexError as e:
        print(f"Caught underflow: {e}")


if __name__ == "__main__":
    main()
