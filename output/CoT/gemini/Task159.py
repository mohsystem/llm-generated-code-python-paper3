def read_from_buffer(buffer, size, index):
    """
    Reads data from a buffer at a given index.

    Args:
        buffer: The dynamically allocated buffer (represented by a list).
        size: The size of the buffer.
        index: The index from which to read data.

    Returns:
        The data at the index if valid, otherwise None.
    """
    # Security: Check if the index is within the valid bounds [0, size-1].
    # This prevents Python's IndexError.
    if 0 <= index < size:
        return buffer[index]
    else:
        # Index is out of bounds, return None to indicate failure.
        return None

def main():
    """Main function to run test cases."""
    BUFFER_SIZE = 10
    # 1. Dynamically allocate a memory buffer.
    # In Python, lists are dynamic arrays.
    buffer = [0] * BUFFER_SIZE

    # 2. Fill the buffer with some data.
    for i in range(BUFFER_SIZE):
        buffer[i] = i * 10  # e.g., 0, 10, 20, ...
    
    print("Python Test Cases:")
    
    # 3. Test cases to read from the buffer.
    test_indices = [3, 0, 9, 10, -1]

    for i, index in enumerate(test_indices):
        print(f"Test {i + 1}: Reading at index {index}... ", end="")
        
        result = read_from_buffer(buffer, BUFFER_SIZE, index)

        if result is not None:
            print(f"Success! Value: {result}")
        else:
            print("Error: Index is out of bounds.")

if __name__ == "__main__":
    main()