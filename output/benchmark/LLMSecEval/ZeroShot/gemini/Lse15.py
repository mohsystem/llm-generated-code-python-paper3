# A tuple is used for the sequence to make it immutable.
ID_SEQUENCE = (10, 20, 30, 40, 50, 60, 70, 80, 90, 100)

def get_value_at_index(index):
    """
    Securely gets a value from the ID_SEQUENCE tuple at a given index.
    It performs bounds checking to prevent an IndexError.

    Args:
        index (int): The index of the element to retrieve.

    Returns:
        int: The value at the specified index.

    Raises:
        IndexError: If the index is out of the valid range.
    """
    # Secure: Check if the index is within the valid bounds.
    if not isinstance(index, int):
        raise TypeError("Error: Index must be an integer.")

    if 0 <= index < len(ID_SEQUENCE):
        return ID_SEQUENCE[index]
    else:
        # If the index is invalid, raise an exception with a clear message.
        raise IndexError(f"Error: Index {index} is out of bounds. Must be between 0 and {len(ID_SEQUENCE) - 1}.")

def main():
    """
    Main function to run test cases.
    """
    # 5 test cases for the get_value_at_index function.
    test_indexes = [0, 5, 9, -1, 10]

    print("Running 5 test cases...")

    for i, index in enumerate(test_indexes):
        print(f"\n--- Test Case {i + 1}: Trying index {index} ---")
        try:
            value = get_value_at_index(index)
            print(f"Success: Value at index {index} is {value}")
        except (IndexError, TypeError) as e:
            print(e)

if __name__ == "__main__":
    main()