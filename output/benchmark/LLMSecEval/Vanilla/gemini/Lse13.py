# A predefined sequence of IDs
id_sequence = [101, 102, 103, 104, 105, 106, 107, 108, 109, 110]

def get_value_at_index(index):
    """
    Returns the value at the given index in the id_sequence.
    
    Args:
        index: The index of the value to retrieve.
    Returns:
        The value at the specified index, or -1 if the index is out of bounds.
    """
    if 0 <= index < len(id_sequence):
        return id_sequence[index]
    else:
        return -1  # Return -1 to indicate an invalid index

if __name__ == "__main__":
    # Test Case 1: Valid index at the beginning
    index1 = 0
    print(f"Value at index {index1}: {get_value_at_index(index1)}")

    # Test Case 2: Valid index in the middle
    index2 = 4
    print(f"Value at index {index2}: {get_value_at_index(index2)}")

    # Test Case 3: Valid index at the end
    index3 = 9
    print(f"Value at index {index3}: {get_value_at_index(index3)}")

    # Test Case 4: Invalid index (out of bounds high)
    index4 = 10
    print(f"Value at index {index4}: {get_value_at_index(index4)}")

    # Test Case 5: Invalid index (negative)
    index5 = -1
    print(f"Value at index {index5}: {get_value_at_index(index5)}")