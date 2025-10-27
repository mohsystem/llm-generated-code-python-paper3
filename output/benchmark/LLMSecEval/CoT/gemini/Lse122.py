import sys

def manage_memory(test_case_data: str):
    """
    Allocates two bytearrays, copies content, and then deletes the references,
    making the objects eligible for garbage collection.
    """
    size = 10
    print("--- Starting Memory Management Demo ---")

    try:
        # 1. Allocate two chunks of memory each of size 10.
        # bytearray is a mutable sequence of integers in the range 0 <= x < 256.
        chunk1 = bytearray(size)
        chunk2 = bytearray(size)
        print(f"1. Allocated two memory chunks of size {size}")

        # Initialize the first chunk.
        source_data = test_case_data.encode('utf-8')
        # Use slicing to safely copy data, preventing buffer overflows.
        len_to_copy = min(len(source_data), size)
        chunk1[:len_to_copy] = source_data[:len_to_copy]
        
        print(f"   Initialized chunk1: {chunk1.hex(' ')}")
        print(f"   (chunk2 is currently empty: {chunk2.hex(' ')})")

        # 2. Copy the contents of the first chunk into the second chunk.
        # Slicing the entire array creates a copy of the contents.
        chunk2[:] = chunk1
        print("2. Copied chunk1 to chunk2.")
        print(f"   Content of chunk2 after copy: {chunk2.hex(' ')}")

        # 3. Free the first chunk.
        # In Python, `del` removes the reference. The garbage collector reclaims
        # the memory if the reference count drops to zero.
        del chunk1
        print("3. Freed first chunk (eligible for garbage collection).")

        # 4. Free the second chunk.
        del chunk2
        print("4. Freed second chunk (eligible for garbage collection).")

    except MemoryError:
        print("Error: Failed to allocate memory.", file=sys.stderr)
    
    print("--- Demo Finished ---\n")


if __name__ == "__main__":
    print(">>> Running 5 Test Cases for Memory Management in Python <<<")
    for i in range(1, 6):
        print(f">>> Test Case #{i} <<<")
        data = f"Data {i}"
        manage_memory(data)