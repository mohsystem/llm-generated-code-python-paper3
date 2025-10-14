from typing import List, TypeVar

T = TypeVar('T')

class Stack:
    """A simple stack implementation using a Python list."""

    def __init__(self) -> None:
        """Initializes an empty stack."""
        self._items: List[T] = []

    def push(self, item: T) -> None:
        """Pushes an item onto the top of the stack."""
        self._items.append(item)

    def pop(self) -> T:
        """
        Removes and returns the item at the top of the stack.
        Raises IndexError if the stack is empty.
        """
        if self.is_empty():
            raise IndexError("pop from an empty stack")
        return self._items.pop()

    def peek(self) -> T:
        """
        Returns the item at the top of the stack without removing it.
        Raises IndexError if the stack is empty.
        """
        if self.is_empty():
            raise IndexError("peek from an empty stack")
        return self._items[-1]

    def is_empty(self) -> bool:
        """Returns True if the stack is empty, False otherwise."""
        return not self._items

    def size(self) -> int:
        """Returns the number of items in the stack."""
        return len(self._items)

def main() -> None:
    """Main function with test cases."""
    # Test Case 1: Push and Peek
    print("--- Test Case 1: Push and Peek ---")
    stack1 = Stack()
    stack1.push(10)
    stack1.push(20)
    stack1.push(30)
    print(f"Pushed 10, 20, 30. Top element (peek): {stack1.peek()}")
    print(f"Stack size: {stack1.size()}")

    # Test Case 2: Push and Pop
    print("\n--- Test Case 2: Push and Pop ---")
    stack2 = Stack()
    stack2.push(10)
    stack2.push(20)
    stack2.push(30)
    print(f"Popped element: {stack2.pop()}")
    print(f"Top element after pop (peek): {stack2.peek()}")
    print(f"Stack size: {stack2.size()}")

    # Test Case 3: Mixed Operations
    print("\n--- Test Case 3: Mixed Operations ---")
    stack3 = Stack()
    stack3.push(10)
    stack3.push(20)
    print(f"Popped element: {stack3.pop()}")
    stack3.push(30)
    print(f"Top element (peek): {stack3.peek()}")
    print(f"Stack size: {stack3.size()}")

    # Test Case 4: Pop from empty stack
    print("\n--- Test Case 4: Pop from empty stack ---")
    stack4 = Stack()
    try:
        stack4.pop()
    except IndexError as e:
        print(f"Successfully caught expected exception: {e}")

    # Test Case 5: Peek from empty stack
    print("\n--- Test Case 5: Peek from empty stack ---")
    stack5 = Stack()
    try:
        stack5.peek()
    except IndexError as e:
        print(f"Successfully caught expected exception: {e}")

if __name__ == "__main__":
    main()