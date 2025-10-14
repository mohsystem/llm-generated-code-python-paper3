
class Queue:
    class Node:
        def __init__(self, data):
            self.data = data
            self.next = None
    
    def __init__(self):
        self.front = None
        self.rear = None
        self.size = 0
    
    def enqueue(self, item):
        if item is None:
            raise ValueError("Cannot enqueue None item")
        
        new_node = self.Node(item)
        
        if self.is_empty():
            self.front = new_node
            self.rear = new_node
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


def main():
    # Test Case 1: Basic enqueue and dequeue operations
    print("Test Case 1: Basic operations")
    queue1 = Queue()
    queue1.enqueue(10)
    queue1.enqueue(20)
    queue1.enqueue(30)
    print(f"Peek: {queue1.peek()}")
    print(f"Dequeue: {queue1.dequeue()}")
    print(f"Peek after dequeue: {queue1.peek()}")
    print()
    
    # Test Case 2: String queue
    print("Test Case 2: String queue")
    queue2 = Queue()
    queue2.enqueue("Hello")
    queue2.enqueue("World")
    queue2.enqueue("Python")
    print(f"Size: {queue2.get_size()}")
    print(f"Dequeue: {queue2.dequeue()}")
    print(f"Dequeue: {queue2.dequeue()}")
    print()
    
    # Test Case 3: Empty queue check
    print("Test Case 3: Empty queue operations")
    queue3 = Queue()
    print(f"Is empty: {queue3.is_empty()}")
    queue3.enqueue(100)
    print(f"Is empty after enqueue: {queue3.is_empty()}")
    queue3.dequeue()
    print(f"Is empty after dequeue: {queue3.is_empty()}")
    print()
    
    # Test Case 4: Multiple operations
    print("Test Case 4: Multiple operations")
    queue4 = Queue()
    for i in range(1, 6):
        queue4.enqueue(i * 10)
    print(f"Size: {queue4.get_size()}")
    while not queue4.is_empty():
        print(f"Dequeue: {queue4.dequeue()}")
    print()
    
    # Test Case 5: Error handling
    print("Test Case 5: Error handling")
    queue5 = Queue()
    try:
        queue5.dequeue()
    except IndexError as e:
        print(f"Caught exception: {e}")
    try:
        queue5.enqueue(None)
    except ValueError as e:
        print(f"Caught exception: {e}")


if __name__ == "__main__":
    main()
