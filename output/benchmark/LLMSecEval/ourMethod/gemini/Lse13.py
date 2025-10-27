import sys

# A predefined sequence of IDs.
id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    """
    Returns the value at the specified index in the global id_sequence.

    Args:
        index (int): The index of the element to retrieve.

    Returns:
        int: The value at the specified index.

    Raises:
        TypeError: If the index is not an integer.
        IndexError: If the index is out of the valid range.
    """
    # Rule #4: Ensure all input is validated.
    if not isinstance(index, int):
        raise TypeError("Error: Index must be an integer.")
    
    # Rule #1: Ensure that all buffer operations strictly adhere to the buffer's boundaries.
    if 0 <= index < len(id_sequence):
        return id_sequence[index]
    else:
        raise IndexError(f"Error: Index {index} is out of bounds.")

def main():
    """
    Main function to run test cases.
    """
    # 5 test cases, including valid, invalid, and wrong type.
    test_indices = [0, 5, 9, -1, 10, 'a']

    print("Running test cases...")
    for i, test_index in enumerate(test_indices):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Attempting to access index: {repr(test_index)}")
        try:
            # Rule #7: Ensure that all exceptions are caught and handled appropriately.
            value = get_value_at_index(test_index)
            print(f"Value at index {test_index}: {value}")
        except (IndexError, TypeError) as e:
            # Writing to stderr for errors is a common practice.
            print(f"{e}", file=sys.stderr)

if __name__ == "__main__":
    main()