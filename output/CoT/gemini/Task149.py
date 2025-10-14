import sys

class Node:
    def __init__(self, data):
        self.data = data
        self.next = None

class Queue:
    def __init__(self):
        self.front = self.rear = None

    def is_empty(self):
        return self.front is None

    def enqueue(self, item):
        """Add an item to the rear of the queue."""
        new_node = Node(item)
        if self.rear is None:
            self.front = self.rear = new_node
            return
        self.rear.next = new_node
        self.rear = new_node

    def dequeue(self):
        """Remove and return the item from the front of the queue."""
        if self.is_empty():
            raise IndexError("Queue is empty. Cannot dequeue.")
        
        temp = self.front
        self.front = temp.next

        if self.front is None:
            self.rear = None
        
        return temp.data

    def peek(self):
        """Return the item at the front of the queue without removing it."""
        if self.is_empty():
            raise IndexError("Queue is empty. Cannot peek.")
        return self.front.data

# Main function with test cases
if __name__ == "__main__":
    print("Python Queue Implementation Test")
    queue = Queue()

    # Test Case 1: Enqueue elements
    print("Test Case 1: Enqueue 10, 20, 30")
    queue.enqueue(10)
    queue.enqueue(20)
    queue.enqueue(30)
    print(f"Front element is: {queue.peek()}")

    # Test Case 2: Dequeue an element
    print("\nTest Case 2: Dequeue")
    print(f"Dequeued element: {queue.dequeue()}")
    print(f"Front element is now: {queue.peek()}")

    # Test Case 3: Enqueue another element
    print("\nTest Case 3: Enqueue 40")
    queue.enqueue(40)
    print(f"Front element is: {queue.peek()}")

    # Test Case 4: Dequeue all elements
    print("\nTest Case 4: Dequeue all elements")
    print(f"Dequeued element: {queue.dequeue()}")  # 20
    print(f"Dequeued element: {queue.dequeue()}")  # 30
    print(f"Dequeued element: {queue.dequeue()}")  # 40
    print(f"Is queue empty? {queue.is_empty()}")

    # Test Case 5: Underflow condition
    print("\nTest Case 5: Underflow condition")
    try:
        queue.peek()
    except IndexError as e:
        print(f"Caught expected exception on peek: {e}")
    try:
        queue.dequeue()
    except IndexError as e:
        print(f"Caught expected exception on dequeue: {e}")