class Stack:
    """
    A secure Stack implementation for integers.
    It uses a Python list, which is a dynamic array, preventing overflow.
    It explicitly checks for underflow on pop and peek operations.
    """
    def __init__(self):
        """Constructs an empty stack."""
        self._stack_list = []

    def is_empty(self):
        """
        Tests if this stack is empty.
        :return: True if the stack is empty, False otherwise.
        """
        return not self._stack_list

    def push(self, item):
        """
        Pushes an element onto the top of the stack.
        :param item: The element to be pushed onto the stack.
        """
        self._stack_list.append(item)

    def pop(self):
        """
        Removes and returns the element at the top of the stack.
        :return: The element at the top of the stack.
        :raises IndexError: if the stack is empty.
        """
        if self.is_empty():
            # Secure: Prevent stack underflow.
            raise IndexError("pop from an empty stack")
        return self._stack_list.pop()

    def peek(self):
        """
        Returns the element at the top of the stack without removing it.
        :return: The element at the top of the stack.
        :raises IndexError: if the stack is empty.
        """
        if self.is_empty():
            # Secure: Prevent stack underflow.
            raise IndexError("peek from an empty stack")
        return self._stack_list[-1]

def main():
    """Main function with test cases for the Stack implementation."""
    print("Python Stack Test Cases:")
    
    # Test Case 1: Basic push and pop
    print("\n--- Test Case 1: Basic Operations ---")
    s1 = Stack()
    s1.push(10)
    s1.push(20)
    print(f"Popped: {s1.pop()}")  # Should be 20
    print(f"Peeked: {s1.peek()}")  # Should be 10
    print(f"Popped: {s1.pop()}")  # Should be 10

    # Test Case 2: Popping from an empty stack
    print("\n--- Test Case 2: Pop from Empty Stack ---")
    s2 = Stack()
    try:
        s2.pop()
    except IndexError as e:
        print(f"Caught expected exception: {e}")

    # Test Case 3: Peeking from an empty stack
    print("\n--- Test Case 3: Peek from Empty Stack ---")
    s3 = Stack()
    try:
        s3.peek()
    except IndexError as e:
        print(f"Caught expected exception: {e}")

    # Test Case 4: A sequence of operations
    print("\n--- Test Case 4: Sequence of Operations ---")
    s4 = Stack()
    s4.push(1)
    s4.push(2)
    s4.push(3)
    print(f"Popped: {s4.pop()}")  # 3
    s4.push(4)
    print(f"Peeked: {s4.peek()}")  # 4
    print(f"Popped: {s4.pop()}")  # 4
    print(f"Popped: {s4.pop()}")  # 2

    # Test Case 5: Check is_empty
    print("\n--- Test Case 5: is_empty Check ---")
    s5 = Stack()
    print(f"Is stack empty? {s5.is_empty()}")  # True
    s5.push(100)
    print(f"Is stack empty? {s5.is_empty()}")  # False
    s5.pop()
    print(f"Is stack empty? {s5.is_empty()}")  # True

if __name__ == "__main__":
    main()