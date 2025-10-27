import gc

def secure_memory_operations():
    """
    Demonstrates allocation, copying, and deallocation of memory chunks in Python.
    Memory is managed automatically by a garbage collector. "Freeing" is done
    by removing references to an object, making it eligible for collection.
    """
    print("--- Python: Starting memory operations ---")
    
    chunk1 = None
    chunk2 = None
    try:
        # 1. Allocate two chunks of memory each of size 10.
        # bytearray is a mutable sequence of bytes.
        chunk1 = bytearray(b'0123456789')
        print("Step 1: Allocated chunk1 (bytearray of size 10).")

        chunk2 = bytearray(10)
        print("Step 2: Allocated chunk2 (bytearray of size 10).")

        # 2. Copy the contents of the first chunk into the second chunk.
        # Slice assignment is a safe way to copy contents in-place.
        chunk2[:] = chunk1
        print(f"Step 3: Copied contents to chunk2. chunk2 is now: {chunk2.decode()}")

    except MemoryError:
        print("Error: Failed to allocate memory.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # 3. Free the first chunk.
        # 'del' removes the reference. If it's the last one, the object is
        # marked for garbage collection.
        if 'chunk1' in locals() or 'chunk1' in globals():
            del chunk1
        print("Step 4: Freed chunk1 by deleting its reference.")

        # 4. Free the second chunk.
        if 'chunk2' in locals() or 'chunk2' in globals():
            del chunk2
        print("Step 5: Freed chunk2 by deleting its reference.")
    
    print("--- Python: Finished memory operations ---")


def main():
    for i in range(5):
        print(f"\nTest Case {i + 1}")
        secure_memory_operations()

if __name__ == "__main__":
    main()