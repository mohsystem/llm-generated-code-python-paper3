class Stack:
    def __init__(self, capacity):
        self.capacity = capacity
        self.stack = []

    def is_empty(self):
        return len(self.stack) == 0

    def is_full(self):
        return len(self.stack) == self.capacity

    def push(self, item):
        if self.is_full():
            print("Stack Overflow")
            return
        print(f"Pushing {item}")
        self.stack.append(item)

    def pop(self):
        if self.is_empty():
            print("Stack Underflow")
            return None
        item = self.stack.pop()
        print(f"Popping {item}")
        return item

    def peek(self):
        if self.is_empty():
            print("Stack is empty")
            return None
        return self.stack[-1]

def main():
    print("--- Python Stack Test ---")
    stack = Stack(3)

    # Test Case 1: Push elements
    stack.push(10)
    stack.push(20)
    stack.push(30)

    # Test Case 2: Peek at the top element
    print(f"Top element is: {stack.peek()}")

    # Test Case 3: Pop an element
    stack.pop()
    print(f"Top element after pop is: {stack.peek()}")

    # Test Case 4: Push to a full stack (Overflow)
    stack.push(40)
    stack.push(50)

    # Test Case 5: Pop all elements and check for underflow
    stack.pop()
    stack.pop()
    stack.pop()
    stack.pop()

if __name__ == "__main__":
    main()