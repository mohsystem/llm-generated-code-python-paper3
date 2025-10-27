# A predefined sequence of IDs.
id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    """
    Retrieves the value from id_sequence at a specified index.

    Args:
        index (int): The index of the value to retrieve.

    Returns:
        int: The integer value at the given index.

    Raises:
        IndexError: If the index is out of the valid range.
    """
    # Security: Check if the index is within the valid bounds of the list.
    if 0 <= index < len(id_sequence):
        return id_sequence[index]
    else:
        # If the index is invalid, raise an exception.
        raise IndexError(f"Error: Index {index} is out of bounds.")

def main():
    """ Main function to run test cases. """
    # 5 test cases for the get_value_at_index function.
    test_indexes = [0, 4, 9, -1, 10]

    print("--- Running Python Test Cases ---")
    for index in test_indexes:
        try:
            value = get_value_at_index(index)
            print(f"Value at index {index}: {value}")
        except IndexError as e:
            print(f"Attempted to access index {index}. {e}")

if __name__ == "__main__":
    main()