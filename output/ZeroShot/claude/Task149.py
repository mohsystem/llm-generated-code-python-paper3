
class Node:
    def __init__(self, data):
        self.data = data
        self.next = None

class Task149:
    def __init__(self):
        self.front = None
        self.rear = None
        self.size = 0
    
    def enqueue(self, data):
        new_node = Node(data)
        if self.rear is None:
            self.front = self.rear = new_node
        else:
            self.rear.next = new_node
            self.rear = new_node
        self.size += 1
    
    def dequeue(self):
        if self.is_empty():
            raise IndexError("Queue is empty")
        data = self.front.data
        self.front = self.front.next
        if self.front is None:
            self.rear = None
        self.size -= 1
        return data
    
    def peek(self):
        if self.is_empty():
            raise IndexError("Queue is empty")
        return self.front.data
    
    def is_empty(self):
        return self.front is None
    
    def get_size(self):
        return self.size

if __name__ == "__main__":
    # Test case 1: Basic enqueue and dequeue
    print("Test Case 1: Basic enqueue and dequeue")
    queue1 = Task149()
    queue1.enqueue(10)
    queue1.enqueue(20)
    queue1.enqueue(30)
    print(f"Dequeue: {queue1.dequeue()}")
    print(f"Peek: {queue1.peek()}")
    print(f"Size: {queue1.get_size()}")
    print()
    
    # Test case 2: Enqueue and peek without dequeue
    print("Test Case 2: Enqueue and peek")
    queue2 = Task149()
    queue2.enqueue(5)
    queue2.enqueue(15)
    print(f"Peek: {queue2.peek()}")
    print(f"Peek again: {queue2.peek()}")
    print(f"Size: {queue2.get_size()}")
    print()
    
    # Test case 3: Multiple operations
    print("Test Case 3: Multiple operations")
    queue3 = Task149()
    queue3.enqueue(1)
    queue3.enqueue(2)
    print(f"Dequeue: {queue3.dequeue()}")
    queue3.enqueue(3)
    queue3.enqueue(4)
    print(f"Dequeue: {queue3.dequeue()}")
    print(f"Peek: {queue3.peek()}")
    print(f"Size: {queue3.get_size()}")
    print()
    
    # Test case 4: Empty queue
    print("Test Case 4: Empty queue check")
    queue4 = Task149()
    print(f"Is empty: {queue4.is_empty()}")
    queue4.enqueue(100)
    print(f"Is empty: {queue4.is_empty()}")
    queue4.dequeue()
    print(f"Is empty after dequeue: {queue4.is_empty()}")
    print()
    
    # Test case 5: Large number of operations
    print("Test Case 5: Large number of operations")
    queue5 = Task149()
    for i in range(1, 6):
        queue5.enqueue(i * 10)
    print(f"Size: {queue5.get_size()}")
    print(f"Dequeue: {queue5.dequeue()}")
    print(f"Dequeue: {queue5.dequeue()}")
    print(f"Peek: {queue5.peek()}")
    print(f"Size: {queue5.get_size()}")
