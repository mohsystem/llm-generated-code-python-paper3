def read_from_buffer(buffer, index):
    """
    Reads an integer value from a buffer (list) at a given index.

    :param buffer: The list (buffer).
    :param index: The index from which to read the data.
    :return: The value at the specified index, or -1 if the index is out of bounds.
    """
    if not isinstance(buffer, list) or index < 0 or index >= len(buffer):
        print(f"Error: Index {index} is out of bounds.")
        return -1  # Return a sentinel value for an invalid index
    return buffer[index]

def main():
    buffer_size = 10

    # 1. Dynamically allocate a memory buffer (a list in Python)
    dynamic_buffer = [0] * buffer_size

    # 2. Initialize the buffer with some data
    for i in range(buffer_size):
        dynamic_buffer[i] = i * 10

    print(f"Buffer created: {dynamic_buffer}")
    print("------------------------------------")

    # 3. Test cases to read data from the buffer
    # Test Case 1: Read from a valid index at the beginning
    index1 = 0
    value1 = read_from_buffer(dynamic_buffer, index1)
    print(f"Reading from index {index1}: {value1}")

    # Test Case 2: Read from a valid index in the middle
    index2 = 5
    value2 = read_from_buffer(dynamic_buffer, index2)
    print(f"Reading from index {index2}: {value2}")

    # Test Case 3: Read from a valid index at the end
    index3 = buffer_size - 1
    value3 = read_from_buffer(dynamic_buffer, index3)
    print(f"Reading from index {index3}: {value3}")

    # Test Case 4: Read from an invalid index (negative)
    index4 = -1
    value4 = read_from_buffer(dynamic_buffer, index4)
    print(f"Reading from index {index4}: {value4}")

    # Test Case 5: Read from an invalid index (out of bounds)
    index5 = buffer_size
    value5 = read_from_buffer(dynamic_buffer, index5)
    print(f"Reading from index {index5}: {value5}")

    # In Python, the garbage collector handles memory deallocation automatically.

if __name__ == "__main__":
    main()