# A predefined constant list of IDs.
id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    """
    Retrieves the value from id_sequence at a specified index.

    Args:
        index: The index of the element to retrieve.

    Returns:
        The value at the specified index.

    Raises:
        IndexError: If the index is out of the valid range.
    """
    # Security Check: Validate that the index is within the bounds of the list.
    if 0 <= index < len(id_sequence):
        return id_sequence[index]
    else:
        # If the index is invalid, raise an exception to indicate the error.
        raise IndexError(f"Error: Index {index} is out of bounds.")

def main():
    # 5 Test Cases
    test_indexes = [3, 0, 9, -1, 10]

    for i, index_to_test in enumerate(test_indexes):
        print(f"Test Case {i + 1}: Testing index {index_to_test}")
        try:
            value = get_value_at_index(index_to_test)
            print(f" -> Success: Value at index {index_to_test} is {value}")
        except IndexError as e:
            print(f" -> {e}")
        print("--------------------")

if __name__ == "__main__":
    main()