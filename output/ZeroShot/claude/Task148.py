
class Stack:
    class Node:
        def __init__(self, data):
            self.data = data
            self.next = None
    
    def __init__(self):
        self.top = None
        self.size = 0
    
    def push(self, data):
        new_node = self.Node(data)
        new_node.next = self.top
        self.top = new_node
        self.size += 1
    
    def pop(self):
        if self.is_empty():
            raise IndexError("Cannot pop from empty stack")
        data = self.top.data
        self.top = self.top.next
        self.size -= 1
        return data
    
    def peek(self):
        if self.is_empty():
            raise IndexError("Cannot peek empty stack")
        return self.top.data
    
    def is_empty(self):
        return self.top is None
    
    def get_size(self):
        return self.size


def main():
    # Test Case 1: Basic push and pop operations
    print("Test Case 1: Basic push and pop")
    stack1 = Stack()
    stack1.push(10)
    stack1.push(20)
    stack1.push(30)
    print(f"Peek: {stack1.peek()}")
    print(f"Pop: {stack1.pop()}")
    print(f"Pop: {stack1.pop()}")
    print(f"Size: {stack1.get_size()}")
    print()
    
    # Test Case 2: Push multiple elements and peek
    print("Test Case 2: Multiple pushes and peek")
    stack2 = Stack()
    for i in range(1, 6):
        stack2.push(i * 10)
    print(f"Peek: {stack2.peek()}")
    print(f"Size: {stack2.get_size()}")
    print()
    
    # Test Case 3: Pop all elements
    print("Test Case 3: Pop all elements")
    stack3 = Stack()
    stack3.push(100)
    stack3.push(200)
    stack3.push(300)
    while not stack3.is_empty():
        print(f"Popped: {stack3.pop()}")
    print(f"Is empty: {stack3.is_empty()}")
    print()
    
    # Test Case 4: Mixed operations
    print("Test Case 4: Mixed operations")
    stack4 = Stack()
    stack4.push(5)
    stack4.push(15)
    print(f"Peek: {stack4.peek()}")
    stack4.pop()
    stack4.push(25)
    stack4.push(35)
    print(f"Peek: {stack4.peek()}")
    print(f"Size: {stack4.get_size()}")
    print()
    
    # Test Case 5: Empty stack exception handling
    print("Test Case 5: Empty stack exception")
    stack5 = Stack()
    try:
        stack5.pop()
    except IndexError as e:
        print(f"Exception caught: {e}")
    try:
        stack5.peek()
    except IndexError as e:
        print(f"Exception caught: {e}")


if __name__ == "__main__":
    main()
