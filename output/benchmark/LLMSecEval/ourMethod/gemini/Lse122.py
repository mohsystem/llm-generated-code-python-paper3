import sys

def manage_memory():
    """
    This function demonstrates basic memory management simulation in Python.
    It allocates two bytearrays, copies the content of one to the other,
    and then makes them eligible for garbage collection.
    """
    chunk_size = 10
    chunk1 = None
    chunk2 = None
    
    try:
        # 1. Allocate two chunks of memory each of size 10.
        chunk1 = bytearray(chunk_size)
        chunk2 = bytearray(chunk_size)
        print(f"Allocated two chunks of size {chunk_size}")

        # Initialize chunk1 with some data for demonstration
        for i in range(chunk_size):
            chunk1[i] = i + 1
        print("Initialized chunk1.")

        # 2. Copy the contents of the first chunk into the second chunk.
        # Slicing is a safe, bounds-checked operation in Python.
        chunk2[:] = chunk1
        print("Copied contents of chunk1 to chunk2.")

        # Verification step
        if chunk1 == chunk2:
            print("Verification successful: chunk2 is a copy of chunk1.")
        else:
            print("Verification failed: copy was not successful.")

    except MemoryError:
        print("Error: Failed to allocate memory.", file=sys.stderr)
        return

    # 3. Free the first chunk.
    # In Python, "freeing" is handled by the garbage collector. `del` removes
    # the name from the local scope, decrementing the object's reference count.
    # When the count reaches zero, the memory is reclaimed.
    del chunk1
    print("Freed chunk1 (by deleting its reference).")

    # 4. Free the second chunk.
    del chunk2
    print("Freed chunk2 (by deleting its reference).")
    print("Memory management simulation complete.")

def main():
    """Main function to run test cases."""
    for i in range(5):
        print(f"\n--- Test Case {i + 1} ---")
        manage_memory()

if __name__ == "__main__":
    main()