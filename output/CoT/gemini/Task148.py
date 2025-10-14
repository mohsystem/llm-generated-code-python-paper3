import sys

class Stack:
    def __init__(self, capacity):
        if not isinstance(capacity, int) or capacity <= 0:
            raise ValueError("Capacity must be a positive integer.")
        self._capacity = capacity
        self._data = []

    def is_empty(self):
        """Check if the stack is empty."""
        return len(self._data) == 0

    def is_full(self):
        """Check if the stack is full."""
        return len(self._data) == self._capacity

    def push(self, item):
        """Push an item onto the top of the stack."""
        if self.is_full():
            print(f"Error: Stack overflow. Cannot push {item}", file=sys.stderr)
            return
        self._data.append(item)
        print(f"Pushed {item} to stack.")

    def pop(self):
        """Pop an item from the top of the stack."""
        if self.is_empty():
            print("Error: Stack underflow. Cannot pop.", file=sys.stderr)
            return None
        item = self._data.pop()
        print(f"Popped {item} from stack.")
        return item

    def peek(self):
        """Peek at the top item of the stack without removing it."""
        if self.is_empty():
            print("Error: Stack is empty. Cannot peek.", file=sys.stderr)
            return None
        return self._data[-1]

def main():
    print("Initializing a stack with capacity 5.")
    stack = Stack(5)

    # Test Case 1: Push items and peek
    print("\n--- Test Case 1: Push and Peek ---")
    stack.push(10)
    stack.push(20)
    stack.push(30)
    print(f"Top element is (peek): {stack.peek()}")

    # Test Case 2: Pop all items
    print("\n--- Test Case 2: Pop All Items ---")
    stack.pop()
    stack.pop()
    stack.pop()

    # Test Case 3: Pop from an empty stack (underflow)
    print("\n--- Test Case 3: Pop from Empty Stack ---")
    print(f"Is stack empty? {stack.is_empty()}")
    stack.pop()  # This should cause an underflow error

    # Test Case 4: Push until the stack is full
    print("\n--- Test Case 4: Fill the Stack ---")
    stack.push(11)
    stack.push(22)
    stack.push(33)
    stack.push(44)
    stack.push(55)
    print(f"Is stack full? {stack.is_full()}")

    # Test Case 5: Push to a full stack (overflow)
    print("\n--- Test Case 5: Push to Full Stack ---")
    stack.push(66)  # This should cause an overflow error
    print(f"Top element is (peek): {stack.peek()}")

if __name__ == "__main__":
    main()