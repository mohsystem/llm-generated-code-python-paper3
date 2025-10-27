import sys

def demonstrate_memory_operations(content_str):
    """
    Demonstrates memory allocation, copying, and freeing concepts in Python.
    Python uses a garbage collector for automatic memory management.
    "Freeing" memory is done by removing references to an object.
    
    Args:
        content_str: The string content to use for the memory chunks.
    """
    print(f"---- Demonstrating for content: \"{content_str}\" ----")
    
    # Use bytearray to represent a mutable chunk of memory
    # 1. Allocate two chunks of memory.
    try:
        # Encode string to bytes for the first chunk
        chunk1 = bytearray(content_str, 'utf-8')
        # Allocate second chunk of the same size
        chunk2 = bytearray(len(chunk1))
    except TypeError as e:
        print(f"Error creating bytearray: {e}", file=sys.stderr)
        return

    # 2. Copy the contents of the first chunk into the second chunk.
    # Slicing is a safe way to copy the contents, preventing overflow.
    chunk2[:] = chunk1
    
    # 3. Print the contents of the second chunk.
    # We decode it back to a string for printing.
    print(f"Contents of chunk2 before freeing chunk1: {chunk2.decode('utf-8')}")
    
    # 4. "Free" the memory allocated to the first chunk.
    # In Python, deleting the reference makes the object eligible for garbage collection.
    del chunk1
    
    print("chunk1 has been deleted (marked for garbage collection).")
    
    # 5. Print the contents of the second chunk again.
    # chunk2 is a separate object, so it's unaffected.
    print(f"Contents of chunk2 after freeing chunk1:  {chunk2.decode('utf-8')}")
    
    # 6. "Free" the memory allocated to the second chunk.
    del chunk2
    print("chunk2 has been deleted (marked for garbage collection).")
    print("------------------------------------------\n")


if __name__ == '__main__':
    # 5 test cases
    demonstrate_memory_operations("Hello, Secure World!")
    demonstrate_memory_operations("")  # Empty string
    demonstrate_memory_operations("A\0B\0C") # String with embedded nulls
    demonstrate_memory_operations("This is a much longer string to test a slightly larger allocation of memory.")
    demonstrate_memory_operations("!@#$%^&*()_+-=[]{}|;':,./<>?")