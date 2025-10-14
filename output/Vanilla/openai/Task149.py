class IntQueue:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.data = [None] * capacity
        self.head = 0
        self.tail = 0
        self.size = 0

    def enqueue(self, x: int) -> bool:
        if self.size == self.capacity:
            return False
        self.data[self.tail] = x
        self.tail = (self.tail + 1) % self.capacity
        self.size += 1
        return True

    def dequeue(self):
        if self.size == 0:
            return None
        val = self.data[self.head]
        self.head = (self.head + 1) % self.capacity
        self.size -= 1
        return val

    def peek(self):
        if self.size == 0:
            return None
        return self.data[self.head]

class Task149:
    @staticmethod
    def run_tests():
        # Test 1: Basic enqueue, peek, and dequeue
        q1 = IntQueue(5)
        q1.enqueue(1)
        q1.enqueue(2)
        q1.enqueue(3)
        print("Test1 Peek:", q1.peek())            # Expect 1
        print("Test1 Dequeue:", q1.dequeue())      # Expect 1
        print("Test1 Peek after dequeue:", q1.peek())  # Expect 2

        # Test 2: Peek on empty queue
        q2 = IntQueue(3)
        print("Test2 Peek on empty:", q2.peek())   # Expect None

        # Test 3: Dequeue on empty queue
        q3 = IntQueue(2)
        print("Test3 Dequeue on empty:", q3.dequeue())  # Expect None

        # Test 4: Fill to capacity and attempt extra enqueue
        q4 = IntQueue(3)
        print("Test4 Enqueue 1:", q4.enqueue(1))  # True
        print("Test4 Enqueue 2:", q4.enqueue(2))  # True
        print("Test4 Enqueue 3:", q4.enqueue(3))  # True
        print("Test4 Enqueue 4 (should fail):", q4.enqueue(4))  # False

        # Test 5: Wrap-around behavior
        q5 = IntQueue(3)
        q5.enqueue(10)
        q5.enqueue(20)
        q5.enqueue(30)
        print("Test5 Dequeue:", q5.dequeue())  # 10
        print("Test5 Dequeue:", q5.dequeue())  # 20
        print("Test5 Enqueue 40:", q5.enqueue(40))  # True
        print("Test5 Enqueue 50:", q5.enqueue(50))  # True
        print("Test5 Dequeue:", q5.dequeue())  # 30
        print("Test5 Dequeue:", q5.dequeue())  # 40
        print("Test5 Dequeue:", q5.dequeue())  # 50
        print("Test5 Dequeue on empty:", q5.dequeue())  # None

if __name__ == "__main__":
    Task149.run_tests()