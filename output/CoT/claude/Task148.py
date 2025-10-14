
class Task148:
    def __init__(self, capacity=10):
        if capacity <= 0:
            raise ValueError("Capacity must be positive")
        self.capacity = capacity
        self.stack = []
        self.top = -1

    def push(self, value):
        if value is None:
            raise ValueError("Cannot push None value")
        self.stack.append(value)
        self.top += 1

    def pop(self):
        if self.is_empty():
            raise IndexError("Cannot pop from empty stack")
        self.top -= 1
        return self.stack.pop()

    def peek(self):
        if self.is_empty():
            raise IndexError("Cannot peek empty stack")
        return self.stack[self.top]

    def is_empty(self):
        return self.top == -1

    def size(self):
        return self.top + 1


def main():
    print("=== Test Case 1: Basic Push and Pop ===")
    stack1 = Task148()
    stack1.push(10)
    stack1.push(20)
    stack1.push(30)
    print(f"Peek: {stack1.peek()}")
    print(f"Pop: {stack1.pop()}")
    print(f"Pop: {stack1.pop()}")
    print(f"Size: {stack1.size()}")

    print("\\n=== Test Case 2: Empty Stack Check ===")
    stack2 = Task148()
    print(f"Is Empty: {stack2.is_empty()}")
    stack2.push(5)
    print(f"Is Empty: {stack2.is_empty()}")
    stack2.pop()
    print(f"Is Empty after pop: {stack2.is_empty()}")

    print("\\n=== Test Case 3: Multiple Operations ===")
    stack3 = Task148()
    for i in range(1, 6):
        stack3.push(i * 10)
    print(f"Stack size: {stack3.size()}")
    print(f"Peek: {stack3.peek()}")
    while not stack3.is_empty():
        print(f"Pop: {stack3.pop()}")

    print("\\n=== Test Case 4: Large Stack ===")
    stack4 = Task148()
    for i in range(100):
        stack4.push(i)
    print(f"Size: {stack4.size()}")
    print(f"Peek: {stack4.peek()}")

    print("\\n=== Test Case 5: Error Handling ===")
    stack5 = Task148()
    try:
        stack5.pop()
    except IndexError as e:
        print(f"Caught exception: {e}")
    try:
        stack5.peek()
    except IndexError as e:
        print(f"Caught exception: {e}")


if __name__ == "__main__":
    main()
