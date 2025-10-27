def allocate_copy_and_print(source_data):
    """
    Allocates two chunks of memory, copies from the first to the second,
    and prints the second.
    """
    try:
        # 1. Allocate the first chunk of memory and initialize it.
        # In Python, creating a bytearray allocates memory.
        first_chunk = bytearray(source_data)

        # 2. Allocate the second chunk of memory.
        # We create a new bytearray of the same size.
        second_chunk = bytearray(len(first_chunk))

        # 3. Copy the contents of the first chunk into the second chunk.
        second_chunk[:] = first_chunk

        # 4. Print the contents of the second chunk.
        # Memory is managed by Python's garbage collector.
        print(f"Contents of the second chunk: {list(second_chunk)}")

    except (TypeError, ValueError) as e:
        print(f"Error processing source data: {e}")

def main():
    print("--- Python Test Cases ---")

    # Test Case 1: Regular list of integers (0-255)
    print("\nTest Case 1:")
    allocate_copy_and_print([10, 20, 30, 40, 50])

    # Test Case 2: Data from a string
    print("\nTest Case 2:")
    allocate_copy_and_print("Hello".encode('utf-8'))

    # Test Case 3: Empty list
    print("\nTest Case 3:")
    allocate_copy_and_print([])

    # Test Case 4: Single element list
    print("\nTest Case 4:")
    allocate_copy_and_print([127])

    # Test Case 5: A bytes object
    print("\nTest Case 5:")
    allocate_copy_and_print(b'\x00\x01\xff\xfe') # 0, 1, 255, 254

if __name__ == "__main__":
    main()