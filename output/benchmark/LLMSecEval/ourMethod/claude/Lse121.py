
import sys
import ctypes

def demonstrate_memory_copy(size):
    """\n    Secure implementation demonstrating memory allocation and copying.\n    Uses ctypes for low-level memory operations similar to C.\n    """
    # Input validation: ensure size is reasonable and positive
    if size <= 0 or size > 1024 * 1024:  # Limit to 1MB
        print("Invalid size", file=sys.stderr)
        return
    
    try:
        # Allocate first chunk and initialize with sample data
        chunk1 = (ctypes.c_ubyte * size)()
        for i in range(size):
            chunk1[i] = i % 256  # Initialize with bounded values
        
        # Allocate second chunk
        chunk2 = (ctypes.c_ubyte * size)()
        
        # Securely copy contents from chunk1 to chunk2 with bounds checking
        ctypes.memmove(chunk2, chunk1, size)
        
        # Print contents of chunk2 (limited output)
        print(f"Contents of chunk2 after copy: {list(chunk2[:min(10, size)])}")
        
        # Clear chunk1 before deletion (important for sensitive data)
        ctypes.memset(chunk1, 0, size)
        del chunk1
        
        # Print contents of chunk2 again (still valid)
        print(f"Contents of chunk2 after chunk1 freed: {list(chunk2[:min(10, size)])}")
        
        # Clear and delete chunk2
        ctypes.memset(chunk2, 0, size)
        del chunk2
        
    except (MemoryError, OverflowError) as e:
        print(f"Memory allocation failed: {e}", file=sys.stderr)
        return

def main():
    # Test case 1: Small allocation
    print("Test 1: Size 10")
    demonstrate_memory_copy(10)
    
    # Test case 2: Medium allocation
    print("\\nTest 2: Size 100")
    demonstrate_memory_copy(100)
    
    # Test case 3: Larger allocation
    print("\\nTest 3: Size 1000")
    demonstrate_memory_copy(1000)
    
    # Test case 4: Edge case - size 1
    print("\\nTest 4: Size 1")
    demonstrate_memory_copy(1)
    
    # Test case 5: Invalid case - negative size
    print("\\nTest 5: Size -1 (invalid)")
    demonstrate_memory_copy(-1)

if __name__ == "__main__":
    main()
