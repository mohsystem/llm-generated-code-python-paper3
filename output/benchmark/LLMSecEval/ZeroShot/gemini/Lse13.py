id_sequence = [101, 102, 103, 104, 105, 106, 107, 108, 109, 110]

def get_value_at_index(index):
    """
    Retrieves the value from the global id_sequence at a specified index.
    This function is secure against index out-of-bounds errors.

    Args:
        index (int): The index of the value to retrieve.

    Returns:
        int: The value at the specified index.

    Raises:
        IndexError: If the index is out of the valid range.
    """
    # Secure: Check if the index is within the valid bounds of the list.
    if not 0 <= index < len(id_sequence):
        raise IndexError(f"Error: Index {index} is out of bounds for the list of size {len(id_sequence)}.")
    return id_sequence[index]

def main():
    """Main function with 5 test cases."""
    # Test cases: valid start, valid middle, valid end, invalid negative, invalid positive
    test_cases = [0, 4, 9, -1, 10]

    print("--- Running Python Test Cases ---")
    for index in test_cases:
        try:
            value = get_value_at_index(index)
            print(f"SUCCESS: Value at index {index} is {value}")
        except IndexError as e:
            print(f"FAILURE: Attempted to access index {index}. {e}")

if __name__ == "__main__":
    main()