import gc

def demonstrate_memory_management(initial_data: str):
    """
    Demonstrates memory allocation, copying, and freeing in Python.
    """
    print(f"Processing data: \"{initial_data}\"")

    # 1. Allocate two chunks of memory and initialize the first one.
    # In Python, bytearray is a mutable sequence of bytes, good for this example.
    chunk1 = bytearray(initial_data, 'utf-8')
    # Allocate the second chunk.
    chunk2 = bytearray(len(chunk1))
    print("Step 1 & 2: Allocated two chunks and initialized first chunk.")

    # 3. Copy the contents of the first chunk into the second chunk.
    # Slicing creates a copy.
    chunk2 = chunk1[:]
    print("Step 3: Copied chunk1 to chunk2.")

    # 4. Print the contents of the second chunk.
    print(f"Step 4: Contents of chunk2 after copy: {chunk2.decode('utf-8')}")

    # 5. Free the memory allocated to the first chunk.
    # In Python, 'del' removes the reference. If the reference count drops to
    # zero, the garbage collector will reclaim the memory.
    print("Step 5: Freed chunk1 (deleted reference).")
    del chunk1
    gc.collect()  # Suggest to the garbage collector to run

    # 6. Print the contents of the second chunk again.
    # The content should remain as chunk2 is an independent copy.
    print(f"Step 6: Contents of chunk2 after freeing chunk1: {chunk2.decode('utf-8')}")

    # 7. Free the memory allocated to the second chunk.
    print("Step 7: Freed chunk2 (deleted reference).")
    del chunk2
    print("----------------------------------------")


if __name__ == "__main__":
    # 5 test cases
    demonstrate_memory_management("Test Case 1: Hello World")
    demonstrate_memory_management("Test Case 2: A simple string")
    demonstrate_memory_management("Test Case 3: Data")
    demonstrate_memory_management("Test Case 4: Another example with numbers 123")
    demonstrate_memory_management("Test Case 5: Final test!")