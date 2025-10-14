class Task149:
    # _Node class for the linked list (internal use)
    class _Node:
        def __init__(self, data):
            self.data = data
            self.next = None

    def __init__(self):
        """Initializes an empty queue."""
        self.front = None
        self.rear = None
        self.size = 0

    def is_empty(self):
        """Checks if the queue is empty."""
        return self.size == 0

    def enqueue(self, data):
        """Adds an element to the rear of the queue."""
        new_node = self._Node(data)
        if self.is_empty():
            self.front = new_node
        else:
            self.rear.next = new_node
        self.rear = new_node
        self.size += 1

    def dequeue(self):
        """
        Removes and returns the element from the front of the queue.
        Raises IndexError if the queue is empty.
        """
        if self.is_empty():
            raise IndexError("Queue is empty. Cannot dequeue.")
        data = self.front.data
        self.front = self.front.next
        if self.front is None:
            self.rear = None
        self.size -= 1
        return data

    def peek(self):
        """
        Returns the element at the front of the queue without removing it.
        Raises IndexError if the queue is empty.
        """
        if self.is_empty():
            raise IndexError("Queue is empty. Cannot peek.")
        return self.front.data

def main():
    queue = Task149()

    # Test Case 1: Enqueue elements
    print("Test Case 1: Enqueue 10, 20, 30")
    queue.enqueue(10)
    queue.enqueue(20)
    queue.enqueue(30)
    print("Enqueue successful.")
    print("--------------------")

    # Test Case 2: Peek at the front element
    print("Test Case 2: Peek front element")
    print(f"Front element is: {queue.peek()}")  # Expected: 10
    print("--------------------")

    # Test Case 3: Dequeue an element
    print("Test Case 3: Dequeue an element")
    print(f"Dequeued element: {queue.dequeue()}")  # Expected: 10
    print(f"Front element after dequeue is: {queue.peek()}")  # Expected: 20
    print("--------------------")

    # Test Case 4: Dequeue all elements
    print("Test Case 4: Dequeue all elements")
    print(f"Dequeued: {queue.dequeue()}")  # Expected: 20
    print(f"Dequeued: {queue.dequeue()}")  # Expected: 30
    print(f"Is queue empty? {queue.is_empty()}")  # Expected: true
    print("--------------------")

    # Test Case 5: Operations on an empty queue (handle exceptions)
    print("Test Case 5: Operations on empty queue")
    try:
        print("Attempting to peek...")
        queue.peek()
    except IndexError as e:
        print(f"Caught expected exception: {e}")
    try:
        print("Attempting to dequeue...")
        queue.dequeue()
    except IndexError as e:
        print(f"Caught expected exception: {e}")
    print("--------------------")

if __name__ == "__main__":
    main()