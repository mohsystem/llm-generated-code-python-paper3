
import sys
import ctypes

# Maximum buffer size to prevent excessive memory allocation
MAX_BUFFER_SIZE = 10485760  # 10 MB

def allocate_and_print_buffer(size: int) -> int:
    """\n    Allocates and prints buffer contents\n    \n    Args:\n        size: The size of buffer to allocate\n    \n    Returns:\n        0 on success, -1 on error\n    """
    # Validate input: check for negative values
    if size < 0:
        print("Error: Buffer size cannot be negative", file=sys.stderr)
        return -1
    
    # Enforce maximum size to prevent excessive memory usage
    if size > MAX_BUFFER_SIZE:
        print("Error: Buffer size exceeds maximum allowed", file=sys.stderr)
        return -1
    
    try:
        # Allocate buffer - bytearray initializes to zero
        buffer = bytearray(size)
        
        # Print buffer contents to stdout (binary safe)
        sys.stdout.buffer.write(buffer)
        sys.stdout.buffer.flush()
        
        # Clear sensitive data using ctypes memset for guaranteed zeroization
        if size > 0:
            buffer_addr = id(buffer) + sys.getsizeof(buffer) - size
            ctypes.memset(buffer_addr, 0, size)
        
        return 0
    except MemoryError:
        # Handle allocation failure without exposing internal details
        print("Error: Unable to allocate buffer", file=sys.stderr)
        return -1
    except Exception:
        # Generic error handling
        print("Error: Operation failed", file=sys.stderr)
        return -1

def main():
    """Main function with test cases"""
    # Test cases when no arguments provided
    if len(sys.argv) == 1:
        print("Running test cases:")
        
        # Test 1: Normal small buffer
        print("\\nTest 1: Size 10")
        allocate_and_print_buffer(10)
        
        # Test 2: Zero size buffer
        print("\\nTest 2: Size 0")
        allocate_and_print_buffer(0)
        
        # Test 3: Moderate size buffer
        print("\\nTest 3: Size 1024")
        allocate_and_print_buffer(1024)
        
        # Test 4: Negative size (should fail)
        print("\\nTest 4: Size -1")
        allocate_and_print_buffer(-1)
        
        # Test 5: Excessive size (should fail)
        print("\\nTest 5: Size exceeding maximum")
        allocate_and_print_buffer(MAX_BUFFER_SIZE + 1)
        
        return
    
    # Validate argument count
    if len(sys.argv) != 2:
        print("Usage: python script.py <buffer_size>", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Parse and validate input with type checking
        size = int(sys.argv[1])
        result = allocate_and_print_buffer(size)
        sys.exit(0 if result == 0 else 1)
    except ValueError:
        # Handle invalid integer format without exposing details
        print("Error: Invalid buffer size", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
