# The predefined sequence of IDs. A tuple is used for immutability.
ID_SEQUENCE = (101, 102, 103, 104, 105, 106, 107, 108, 109, 110)

def get_value_at_index(index: int) -> int:
    """
    Returns the value at the specified index in the ID_SEQUENCE.

    Args:
        index: The index of the element to return.

    Returns:
        The integer value at the specified index.

    Raises:
        IndexError: If the index is out of range.
        TypeError: If the index is not an integer.
    """
    # Rule #1: Ensure all input is validated.
    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")
    
    # Rule #3: Ensure that all buffer operations strictly adhere to the buffer's boundaries.
    if 0 <= index < len(ID_SEQUENCE):
        return ID_SEQUENCE[index]
    else:
        raise IndexError(f"Index {index} is out of bounds for the sequence of length {len(ID_SEQUENCE)}")

def main():
    """ Main function with 5 test cases. """
    test_indices = [0, 9, 5, -1, 10]

    for index in test_indices:
        print(f"Testing with index: {index}")
        try:
            # Rule #5: Ensure that all exceptions are caught and handled appropriately.
            value = get_value_at_index(index)
            print(f"Value at index {index}: {value}")
        except (IndexError, TypeError) as e:
            print(f"Error: {e}")
        print("--------------------")

if __name__ == "__main__":
    main()