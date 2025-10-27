
import ctypes
import sys

def allocate_copy_and_free():
    """\n    Allocates two chunks of memory, copies from first to second, then frees both.\n    Uses ctypes for C-like memory management with Python safety.\n    """
    chunk1 = None
    chunk2 = None
    
    try:
        # Allocate first chunk of 10 bytes - ctypes provides bounds checking
        chunk1 = (ctypes.c_ubyte * 10)()
        if chunk1 is None:
            raise MemoryError("Failed to allocate chunk1")
        
        # Initialize chunk1 with sample data for testing
        for i in range(10):
            chunk1[i] = i
        
        # Allocate second chunk of 10 bytes
        chunk2 = (ctypes.c_ubyte * 10)()
        if chunk2 is None:
            raise MemoryError("Failed to allocate chunk2")
        
        # Copy contents from chunk1 to chunk2 with bounds validation
        # ctypes.memmove provides safe memory copy
        ctypes.memmove(chunk2, chunk1, 10)
        
        # Clear sensitive data from chunk1 before deletion
        ctypes.memset(chunk1, 0, 10)
        del chunk1
        chunk1 = None
        
        # Clear sensitive data from chunk2 before deletion
        ctypes.memset(chunk2, 0, 10)
        del chunk2
        chunk2 = None
        
    except MemoryError as e:
        print(f"Memory allocation failed: {e}", file=sys.stderr)
        # Ensure cleanup on error
        if chunk1 is not None:
            ctypes.memset(chunk1, 0, 10)
            del chunk1
        if chunk2 is not None:
            ctypes.memset(chunk2, 0, 10)
            del chunk2
    except Exception as e:
        print(f"Operation failed: {e}", file=sys.stderr)
        # Ensure cleanup on error
        if chunk1 is not None:
            ctypes.memset(chunk1, 0, 10)
            del chunk1
        if chunk2 is not None:
            ctypes.memset(chunk2, 0, 10)
            del chunk2

if __name__ == "__main__":
    # Test case 1: Normal operation
    print("Test 1: Normal allocation, copy, and free")
    allocate_copy_and_free()
    
    # Test case 2: Repeated operations
    print("Test 2: Repeated operations")
    allocate_copy_and_free()
    
    # Test case 3: Multiple sequential calls
    print("Test 3: Multiple sequential calls")
    for i in range(3):
        allocate_copy_and_free()
    
    # Test case 4: Single operation
    print("Test 4: Single operation")
    allocate_copy_and_free()
    
    # Test case 5: Final operation
    print("Test 5: Final operation")
    allocate_copy_and_free()
    
    print("All tests completed successfully")
