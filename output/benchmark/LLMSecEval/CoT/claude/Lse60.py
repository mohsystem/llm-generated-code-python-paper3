
import sys

MAX_BUFFER_SIZE = 1024 * 1024  # 1MB limit

def allocate_and_print_buffer(size):
    """\n    Securely allocate and print buffer contents\n    """
    # Input validation
    if not isinstance(size, int):
        return "Error: Buffer size must be an integer"
    
    if size <= 0:
        return "Error: Buffer size must be positive"
    
    if size > MAX_BUFFER_SIZE:
        return f"Error: Buffer size exceeds maximum allowed ({MAX_BUFFER_SIZE} bytes)"
    
    try:
        # Allocate buffer and initialize with zeros for security
        buffer = bytearray(size)
        
        # Print buffer contents (safely, limit output)
        display_size = min(size, 100)
        buffer_str = ", ".join(str(b) for b in buffer[:display_size])
        if size > 100:
            buffer_str += "..."
        
        return f"Buffer contents ({size} bytes): [{buffer_str}]"
    except MemoryError:
        return "Error: Unable to allocate buffer - out of memory"

def main():
    # Test cases
    print("Test Case 1 (valid size 10):")
    print(allocate_and_print_buffer(10))
    print()
    
    print("Test Case 2 (valid size 50):")
    print(allocate_and_print_buffer(50))
    print()
    
    print("Test Case 3 (negative size):")
    print(allocate_and_print_buffer(-5))
    print()
    
    print("Test Case 4 (zero size):")
    print(allocate_and_print_buffer(0))
    print()
    
    print("Test Case 5 (excessive size):")
    print(allocate_and_print_buffer(MAX_BUFFER_SIZE + 1))
    print()
    
    # Command line argument handling
    if len(sys.argv) > 1:
        try:
            size = int(sys.argv[1])
            print("Command line argument:")
            print(allocate_and_print_buffer(size))
        except ValueError:
            print("Error: Invalid number format")

if __name__ == "__main__":
    main()
