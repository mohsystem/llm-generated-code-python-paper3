
import ctypes

def demonstrate_memory_copy():
    # Allocate two chunks of memory
    size = 10
    chunk1 = (ctypes.c_char * size)()
    chunk2 = (ctypes.c_char * size)()
    
    # Fill first chunk with some data
    for i in range(size):
        chunk1[i] = chr(i + 65).encode('ascii')[0]
    
    # Copy contents of first chunk into second chunk
    ctypes.memmove(chunk2, chunk1, size)
    
    # Print contents of second chunk
    print("Contents of chunk2 after copy:")
    for i in range(size):
        print(chr(chunk2[i]), end=" ")
    print()
    
    # Free memory allocated to first chunk (Python handles this automatically)
    # We simulate by deleting the reference
    del chunk1
    
    # Print contents of second chunk again
    print("Contents of chunk2 after freeing chunk1:")
    for i in range(size):
        print(chr(chunk2[i]), end=" ")
    print()
    
    # Free memory allocated to second chunk
    del chunk2
    
    print("Both chunks freed.")

if __name__ == "__main__":
    print("Test Case 1:")
    demonstrate_memory_copy()
    
    print("\\nTest Case 2:")
    demonstrate_memory_copy()
    
    print("\\nTest Case 3:")
    demonstrate_memory_copy()
    
    print("\\nTest Case 4:")
    demonstrate_memory_copy()
    
    print("\\nTest Case 5:")
    demonstrate_memory_copy()
