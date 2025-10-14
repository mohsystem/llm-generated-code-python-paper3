
class Task159:
    BUFFER_SIZE = 100
    
    @staticmethod
    def allocate_buffer(size):
        """Dynamically allocate a buffer with size validation"""
        if size <= 0 or size > 1000000:
            raise ValueError("Invalid buffer size")
        return [0] * size
    
    @staticmethod
    def initialize_buffer(buffer):
        """Initialize buffer with sample data"""
        for i in range(len(buffer)):
            buffer[i] = i * 10
    
    @staticmethod
    def read_from_buffer(buffer, index):
        """Securely read data from buffer with bounds checking"""
        if buffer is None:
            raise ValueError("Buffer cannot be None")
        if not isinstance(index, int):
            raise TypeError("Index must be an integer")
        if index < 0 or index >= len(buffer):
            raise IndexError(f"Index out of bounds: {index}")
        return buffer[index]


def main():
    print("=== Secure Memory Buffer Access Test Cases ===\\n")
    
    # Test Case 1: Normal valid access
    try:
        buffer1 = Task159.allocate_buffer(Task159.BUFFER_SIZE)
        Task159.initialize_buffer(buffer1)
        result = Task159.read_from_buffer(buffer1, 50)
        print(f"Test 1 - Valid access at index 50: {result}")
    except Exception as e:
        print(f"Test 1 - Error: {e}")
    
    # Test Case 2: Access at boundary (first element)
    try:
        buffer2 = Task159.allocate_buffer(Task159.BUFFER_SIZE)
        Task159.initialize_buffer(buffer2)
        result = Task159.read_from_buffer(buffer2, 0)
        print(f"Test 2 - Valid access at index 0: {result}")
    except Exception as e:
        print(f"Test 2 - Error: {e}")
    
    # Test Case 3: Access at boundary (last element)
    try:
        buffer3 = Task159.allocate_buffer(Task159.BUFFER_SIZE)
        Task159.initialize_buffer(buffer3)
        result = Task159.read_from_buffer(buffer3, Task159.BUFFER_SIZE - 1)
        print(f"Test 3 - Valid access at index {Task159.BUFFER_SIZE - 1}: {result}")
    except Exception as e:
        print(f"Test 3 - Error: {e}")
    
    # Test Case 4: Invalid access (negative index)
    try:
        buffer4 = Task159.allocate_buffer(Task159.BUFFER_SIZE)
        Task159.initialize_buffer(buffer4)
        result = Task159.read_from_buffer(buffer4, -5)
        print(f"Test 4 - Access at index -5: {result}")
    except Exception as e:
        print(f"Test 4 - Error (Expected): {e}")
    
    # Test Case 5: Invalid access (out of bounds)
    try:
        buffer5 = Task159.allocate_buffer(Task159.BUFFER_SIZE)
        Task159.initialize_buffer(buffer5)
        result = Task159.read_from_buffer(buffer5, 150)
        print(f"Test 5 - Access at index 150: {result}")
    except Exception as e:
        print(f"Test 5 - Error (Expected): {e}")


if __name__ == "__main__":
    main()
