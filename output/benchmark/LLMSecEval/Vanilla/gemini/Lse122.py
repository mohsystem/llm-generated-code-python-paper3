def demonstrate_memory_operations():
    """
    Allocates two bytearrays, copies content, and then deletes them.
    """
    # 1. Allocate two chunks of memory each of size 10.
    # In Python, bytearray is a mutable sequence of bytes. Memory is managed automatically.
    try:
        chunk1 = bytearray(10)
        chunk2 = bytearray(10)
        print("Allocated two bytearrays (chunks) of size 10.")
    except MemoryError:
        print("Memory allocation failed.")
        return

    # For demonstration, fill the first chunk with some data.
    for i in range(10):
        chunk1[i] = i + 1

    # 2. Copy the contents of the first chunk into the second chunk.
    # Slicing is an easy way to copy the contents.
    chunk2[:] = chunk1[:]
    print("Copied contents from chunk1 to chunk2.")
    
    # 3. Free the first chunk.
    # In Python, 'del' removes the name reference. The garbage collector
    # reclaims memory when an object's reference count drops to zero.
    del chunk1
    print("Freed the first chunk (deleted reference).")
    
    # 4. Free the second chunk.
    del chunk2
    print("Freed the second chunk (deleted reference).")

def main():
    """ Main function to run test cases. """
    print("--- Running Python Test Cases ---")
    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        demonstrate_memory_operations()
        print(f"--- End of Test Case {i} ---")

if __name__ == "__main__":
    main()