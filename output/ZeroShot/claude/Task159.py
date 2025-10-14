
class Task159:
    def __init__(self):
        self.BUFFER_SIZE = 100
        self.buffer = [i * 10 for i in range(self.BUFFER_SIZE)]
    
    def read_from_buffer(self, index):
        """Securely read from buffer with bounds checking"""
        if not isinstance(index, int):
            print("Error: Index must be an integer")
            return None
        
        if index < 0 or index >= len(self.buffer):
            print(f"Error: Index out of bounds. Valid range: 0-{len(self.buffer) - 1}")
            return None
        
        return self.buffer[index]
    
    def get_buffer_size(self):
        return len(self.buffer)


def main():
    task = Task159()
    
    print("=== Test Cases ===\\n")
    
    # Test case 1: Valid index at start
    print("Test 1 - Valid index (0):")
    result1 = task.read_from_buffer(0)
    if result1 is not None:
        print(f"Value at index 0: {result1}")
    print()
    
    # Test case 2: Valid index in middle
    print("Test 2 - Valid index (50):")
    result2 = task.read_from_buffer(50)
    if result2 is not None:
        print(f"Value at index 50: {result2}")
    print()
    
    # Test case 3: Valid index at end
    print("Test 3 - Valid index (99):")
    result3 = task.read_from_buffer(99)
    if result3 is not None:
        print(f"Value at index 99: {result3}")
    print()
    
    # Test case 4: Invalid negative index
    print("Test 4 - Invalid negative index (-5):")
    result4 = task.read_from_buffer(-5)
    print()
    
    # Test case 5: Invalid index beyond bounds
    print("Test 5 - Invalid index beyond bounds (150):")
    result5 = task.read_from_buffer(150)
    print()


if __name__ == "__main__":
    main()
