
from typing import Optional, List


class Queue:
    DEFAULT_CAPACITY: int = 10
    MAX_CAPACITY: int = 1000000
    
    def __init__(self, initial_capacity: int = DEFAULT_CAPACITY) -> None:
        if not isinstance(initial_capacity, int) or initial_capacity <= 0 or initial_capacity > self.MAX_CAPACITY:
            raise ValueError(f"Invalid capacity: {initial_capacity}")
        
        self._capacity: int = initial_capacity
        self._data: List[Optional[int]] = [None] * self._capacity
        self._front: int = 0
        self._rear: int = -1
        self._size: int = 0
    
    def enqueue(self, value: int) -> bool:
        if not isinstance(value, int):
            return False
        
        if self._size >= self._capacity:
            if self._capacity >= self.MAX_CAPACITY:
                return False
            self._resize()
        
        self._rear = (self._rear + 1) % self._capacity
        self._data[self._rear] = value
        self._size += 1
        return True
    
    def dequeue(self) -> Optional[int]:
        if self.is_empty():
            return None
        
        value = self._data[self._front]
        self._data[self._front] = None
        self._front = (self._front + 1) % self._capacity
        self._size -= 1
        return value
    
    def peek(self) -> Optional[int]:
        if self.is_empty():
            return None
        return self._data[self._front]
    
    def is_empty(self) -> bool:
        return self._size == 0
    
    def get_size(self) -> int:
        return self._size
    
    def _resize(self) -> None:
        new_capacity = min(self._capacity * 2, self.MAX_CAPACITY)
        
        if new_capacity <= self._capacity:
            return
        
        new_data: List[Optional[int]] = [None] * new_capacity
        for i in range(self._size):
            new_data[i] = self._data[(self._front + i) % self._capacity]
        
        self._data = new_data
        self._front = 0
        self._rear = self._size - 1
        self._capacity = new_capacity


def main() -> None:
    # Test case 1: Basic enqueue and dequeue
    print("Test 1: Basic operations")
    queue1 = Queue(5)
    queue1.enqueue(10)
    queue1.enqueue(20)
    queue1.enqueue(30)
    print(f"Peek: {queue1.peek()}")
    print(f"Dequeue: {queue1.dequeue()}")
    print(f"Dequeue: {queue1.dequeue()}")
    print(f"Size: {queue1.get_size()}")
    print()
    
    # Test case 2: Empty queue operations
    print("Test 2: Empty queue")
    queue2 = Queue()
    print(f"Peek empty: {queue2.peek()}")
    print(f"Dequeue empty: {queue2.dequeue()}")
    print(f"Is empty: {queue2.is_empty()}")
    print()
    
    # Test case 3: Queue with resize
    print("Test 3: Resize operations")
    queue3 = Queue(3)
    for i in range(1, 6):
        queue3.enqueue(i * 10)
    print(f"Size after enqueue: {queue3.get_size()}")
    while not queue3.is_empty():
        print(f"Dequeue: {queue3.dequeue()}")
    print()
    
    # Test case 4: Circular behavior
    print("Test 4: Circular behavior")
    queue4 = Queue(3)
    queue4.enqueue(1)
    queue4.enqueue(2)
    queue4.dequeue()
    queue4.enqueue(3)
    queue4.enqueue(4)
    print(f"Peek: {queue4.peek()}")
    print(f"Size: {queue4.get_size()}")
    print()
    
    # Test case 5: Multiple operations
    print("Test 5: Mixed operations")
    queue5 = Queue()
    queue5.enqueue(100)
    print(f"Peek: {queue5.peek()}")
    queue5.enqueue(200)
    queue5.enqueue(300)
    print(f"Dequeue: {queue5.dequeue()}")
    queue5.enqueue(400)
    print(f"Size: {queue5.get_size()}")
    print(f"Peek: {queue5.peek()}")


if __name__ == "__main__":
    main()
