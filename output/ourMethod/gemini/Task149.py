import sys
from typing import Optional

class Queue:
    """
    A simple Queue implementation using a linked list.
    """
    class _Node:
        """
        Inner class for a node in the linked list.
        """
        def __init__(self, data: int):
            self.data: int = data
            self.next: Optional[Queue._Node] = None

    def __init__(self):
        """
        Initializes an empty queue.
        """
        self._front: Optional[Queue._Node] = None
        self._rear: Optional[Queue._Node] = None

    def is_empty(self) -> bool:
        """
        Checks if the queue is empty.
        :return: True if the queue is empty, False otherwise.
        """
        return self._front is None

    def enqueue(self, data: int) -> None:
        """
        Adds an element to the rear of the queue.
        :param data: The integer data to add.
        """
        new_node = self._Node(data)
        if self.is_empty():
            self._front = new_node
            self._rear = new_node
        else:
            if self._rear:
                self._rear.next = new_node
            self._rear = new_node

    def dequeue(self) -> int:
        """
        Removes and returns the element from the front of the queue.
        :return: The data from the front of the queue.
        :raises IndexError: if the queue is empty.
        """
        if self.is_empty() or self._front is None:
            raise IndexError("dequeue from empty queue")
        data = self._front.data
        self._front = self._front.next
        if self._front is None:
            self._rear = None  # The queue is now empty
        return data

    def peek(self) -> int:
        """
        Returns the element at the front of the queue without removing it.
        :return: The data from the front of the queue.
        :raises IndexError: if the queue is empty.
        """
        if self.is_empty() or self._front is None:
            raise IndexError("peek from empty queue")
        return self._front.data

def main():
    """
    Main function with test cases.
    """
    print("--- Python Queue Test Cases ---")

    # Test Case 1: Basic enqueue and dequeue
    print("\n--- Test Case 1: Basic Operations ---")
    q1 = Queue()
    q1.enqueue(10)
    q1.enqueue(20)
    print(f"Dequeued: {q1.dequeue()}")  # Expected: 10
    print(f"Peek: {q1.peek()}")        # Expected: 20
    print(f"Dequeued: {q1.dequeue()}")  # Expected: 20
    print(f"Is empty: {q1.is_empty()}") # Expected: True

    # Test Case 2: Dequeue from an empty queue
    print("\n--- Test Case 2: Dequeue from Empty Queue ---")
    q2 = Queue()
    try:
        q2.dequeue()
    except IndexError as e:
        print(f"Caught expected exception: {e}")

    # Test Case 3: Peek at an empty queue
    print("\n--- Test Case 3: Peek at Empty Queue ---")
    try:
        q2.peek()
    except IndexError as e:
        print(f"Caught expected exception: {e}")

    # Test Case 4: Enqueue after emptying the queue
    print("\n--- Test Case 4: Enqueue after Emptying ---")
    q4 = Queue()
    q4.enqueue(1)
    q4.enqueue(2)
    q4.dequeue()
    q4.dequeue()
    q4.enqueue(3)
    print(f"Peek: {q4.peek()}")       # Expected: 3
    print(f"Is empty: {q4.is_empty()}") # Expected: False

    # Test Case 5: Multiple operations
    print("\n--- Test Case 5: Multiple Operations ---")
    q5 = Queue()
    q5.enqueue(100)
    q5.enqueue(200)
    q5.enqueue(300)
    print(f"Dequeued: {q5.dequeue()}") # Expected: 100
    q5.enqueue(400)
    print(f"Peek: {q5.peek()}")       # Expected: 200
    print(f"Dequeued: {q5.dequeue()}") # Expected: 200
    print(f"Dequeued: {q5.dequeue()}") # Expected: 300
    print(f"Peek: {q5.peek()}")       # Expected: 400

if __name__ == "__main__":
    main()