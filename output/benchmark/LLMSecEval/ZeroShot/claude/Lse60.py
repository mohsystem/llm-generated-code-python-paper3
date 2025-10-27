
import sys

def print_buffer(size):
    if size <= 0:
        print("Buffer size must be positive")
        return
    
    # Allocate buffer with specified size
    buffer = bytearray(size)
    
    # Print buffer contents
    print(f"Buffer contents: {list(buffer)}")

def main():
    # Test cases
    print("Test Case 1:")
    print_buffer(5)
    
    print("\\nTest Case 2:")
    print_buffer(10)
    
    print("\\nTest Case 3:")
    print_buffer(1)
    
    print("\\nTest Case 4:")
    print_buffer(0)
    
    print("\\nTest Case 5:")
    print_buffer(20)
    
    # Command line argument handling
    if len(sys.argv) > 1:
        try:
            size = int(sys.argv[1])
            print("\\nCommand line argument:")
            print_buffer(size)
        except ValueError:
            print("Invalid argument. Please provide a valid integer.")

if __name__ == "__main__":
    main()
