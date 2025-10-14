
class Task159:
    def __init__(self):
        self.buffer = None
        self.buffer_size = 0
    
    def initialize_buffer(self, size, initial_data=None):
        self.buffer_size = size
        self.buffer = [0] * size
        if initial_data is not None:
            for i in range(min(size, len(initial_data))):
                self.buffer[i] = initial_data[i]
    
    def read_from_buffer(self, index):
        if self.buffer is None:
            print("Error: Buffer not initialized")
            return None
        if index < 0 or index >= self.buffer_size:
            print("Error: Index out of bounds")
            return None
        return self.buffer[index]
    
    def deallocate_buffer(self):
        self.buffer = None
        self.buffer_size = 0


def main():
    # Test case 1: Basic read operation
    print("Test Case 1: Basic read operation")
    task = Task159()
    data1 = [10, 20, 30, 40, 50]
    task.initialize_buffer(5, data1)
    result = task.read_from_buffer(2)
    print(f"Read from index 2: {result}")
    task.deallocate_buffer()
    print()
    
    # Test case 2: Read from first index
    print("Test Case 2: Read from first index")
    task = Task159()
    data2 = [100, 200, 300]
    task.initialize_buffer(3, data2)
    result = task.read_from_buffer(0)
    print(f"Read from index 0: {result}")
    task.deallocate_buffer()
    print()
    
    # Test case 3: Read from last index
    print("Test Case 3: Read from last index")
    task = Task159()
    data3 = [5, 15, 25, 35, 45, 55]
    task.initialize_buffer(6, data3)
    result = task.read_from_buffer(5)
    print(f"Read from index 5: {result}")
    task.deallocate_buffer()
    print()
    
    # Test case 4: Invalid index (negative)
    print("Test Case 4: Invalid index (negative)")
    task = Task159()
    data4 = [1, 2, 3, 4]
    task.initialize_buffer(4, data4)
    result = task.read_from_buffer(-1)
    print(f"Result: {result}")
    task.deallocate_buffer()
    print()
    
    # Test case 5: Invalid index (out of bounds)
    print("Test Case 5: Invalid index (out of bounds)")
    task = Task159()
    data5 = [7, 14, 21, 28]
    task.initialize_buffer(4, data5)
    result = task.read_from_buffer(10)
    print(f"Result: {result}")
    task.deallocate_buffer()
    print()


if __name__ == "__main__":
    main()
