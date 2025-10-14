import collections

class Queue:
    def __init__(self):
        self.items = collections.deque()

    def is_empty(self):
        return not self.items

    def enqueue(self, item):
        self.items.append(item)

    def dequeue(self):
        if self.is_empty():
            print("Error: Queue is empty")
            return None
        return self.items.popleft()

    def peek(self):
        if self.is_empty():
            print("Error: Queue is empty")
            return None
        return self.items[0]

def main():
    q = Queue()

    print("--- Test Case 1: Enqueue and Peek ---")
    q.enqueue(10)
    q.enqueue(20)
    q.enqueue(30)
    print(f"Peek: {q.peek()}")  # Expected: 10

    print("\n--- Test Case 2: Dequeue and Peek ---")
    print(f"Dequeued: {q.dequeue()}")  # Expected: 10
    print(f"Peek: {q.peek()}")  # Expected: 20

    print("\n--- Test Case 3: Dequeue multiple ---")
    print(f"Dequeued: {q.dequeue()}")  # Expected: 20
    print(f"Dequeued: {q.dequeue()}")  # Expected: 30

    print("\n--- Test Case 4: Operations on empty queue ---")
    print(f"Peek: {q.peek()}")  # Expected: Error, None
    print(f"Dequeued: {q.dequeue()}")  # Expected: Error, None

    print("\n--- Test Case 5: Enqueue after empty ---")
    q.enqueue(40)
    q.enqueue(50)
    print(f"Peek: {q.peek()}")  # Expected: 40
    print(f"Dequeued: {q.dequeue()}")  # Expected: 40
    print(f"Peek: {q.peek()}")  # Expected: 50

if __name__ == "__main__":
    main()