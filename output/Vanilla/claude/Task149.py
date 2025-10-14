
class Task149:
    def __init__(self):
        self.queue = []
    
    def enqueue(self, value):
        self.queue.append(value)
    
    def dequeue(self):
        if not self.queue:
            return None
        return self.queue.pop(0)
    
    def peek(self):
        if not self.queue:
            return None
        return self.queue[0]
    
    def is_empty(self):
        return len(self.queue) == 0
    
    def size(self):
        return len(self.queue)


if __name__ == "__main__":
    # Test Case 1: Basic enqueue and dequeue
    print("Test Case 1: Basic enqueue and dequeue")
    q1 = Task149()
    q1.enqueue(10)
    q1.enqueue(20)
    q1.enqueue(30)
    print(f"Dequeue: {q1.dequeue()}")  # 10
    print(f"Dequeue: {q1.dequeue()}")  # 20
    print()
    
    # Test Case 2: Peek operation
    print("Test Case 2: Peek operation")
    q2 = Task149()
    q2.enqueue(5)
    q2.enqueue(15)
    print(f"Peek: {q2.peek()}")  # 5
    print(f"Peek: {q2.peek()}")  # 5
    print(f"Dequeue: {q2.dequeue()}")  # 5
    print(f"Peek: {q2.peek()}")  # 15
    print()
    
    # Test Case 3: Empty queue operations
    print("Test Case 3: Empty queue operations")
    q3 = Task149()
    print(f"Dequeue from empty: {q3.dequeue()}")  # None
    print(f"Peek from empty: {q3.peek()}")  # None
    q3.enqueue(100)
    print(f"Dequeue: {q3.dequeue()}")  # 100
    print(f"Dequeue from empty: {q3.dequeue()}")  # None
    print()
    
    # Test Case 4: Multiple operations
    print("Test Case 4: Multiple operations")
    q4 = Task149()
    q4.enqueue(1)
    q4.enqueue(2)
    print(f"Dequeue: {q4.dequeue()}")  # 1
    q4.enqueue(3)
    q4.enqueue(4)
    print(f"Peek: {q4.peek()}")  # 2
    print(f"Dequeue: {q4.dequeue()}")  # 2
    print(f"Dequeue: {q4.dequeue()}")  # 3
    print()
    
    # Test Case 5: Size check
    print("Test Case 5: Size check")
    q5 = Task149()
    print(f"Size: {q5.size()}")  # 0
    q5.enqueue(50)
    q5.enqueue(60)
    q5.enqueue(70)
    print(f"Size: {q5.size()}")  # 3
    q5.dequeue()
    print(f"Size after dequeue: {q5.size()}")  # 2
    print(f"Is empty: {q5.is_empty()}")  # False
