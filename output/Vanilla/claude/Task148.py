
class Node:
    def __init__(self, data):
        self.data = data
        self.next = None

class Stack:
    def __init__(self):
        self.top = None
        self.size = 0
    
    def push(self, data):
        new_node = Node(data)
        new_node.next = self.top
        self.top = new_node
        self.size += 1
    
    def pop(self):
        if self.is_empty():
            raise IndexError("Pop from empty stack")
        data = self.top.data
        self.top = self.top.next
        self.size -= 1
        return data
    
    def peek(self):
        if self.is_empty():
            raise IndexError("Peek from empty stack")
        return self.top.data
    
    def is_empty(self):
        return self.top is None
    
    def get_size(self):
        return self.size

def main():
    # Test Case 1: Basic push and peek
    print("Test Case 1: Basic push and peek")
    stack1 = Stack()
    stack1.push(10)
    stack1.push(20)
    stack1.push(30)
    print(f"Peek: {stack1.peek()}")
    print(f"Size: {stack1.get_size()}")
    print()
    
    # Test Case 2: Pop operations
    print("Test Case 2: Pop operations")
    stack2 = Stack()
    stack2.push(5)
    stack2.push(15)
    stack2.push(25)
    print(f"Pop: {stack2.pop()}")
    print(f"Pop: {stack2.pop()}")
    print(f"Peek: {stack2.peek()}")
    print(f"Size: {stack2.get_size()}")
    print()
    
    # Test Case 3: Push and pop multiple elements
    print("Test Case 3: Push and pop multiple elements")
    stack3 = Stack()
    for i in range(1, 6):
        stack3.push(i * 10)
    print(f"Peek: {stack3.peek()}")
    while not stack3.is_empty():
        print(f"Pop: {stack3.pop()}")
    print(f"Is Empty: {stack3.is_empty()}")
    print()
    
    # Test Case 4: Single element operations
    print("Test Case 4: Single element operations")
    stack4 = Stack()
    stack4.push(100)
    print(f"Peek: {stack4.peek()}")
    print(f"Pop: {stack4.pop()}")
    print(f"Is Empty: {stack4.is_empty()}")
    print()
    
    # Test Case 5: Mixed operations
    print("Test Case 5: Mixed operations")
    stack5 = Stack()
    stack5.push(7)
    stack5.push(14)
    print(f"Peek: {stack5.peek()}")
    stack5.push(21)
    print(f"Pop: {stack5.pop()}")
    stack5.push(28)
    print(f"Peek: {stack5.peek()}")
    print(f"Size: {stack5.get_size()}")

if __name__ == "__main__":
    main()
