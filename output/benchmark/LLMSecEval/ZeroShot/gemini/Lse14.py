# The sequence of IDs, defined as a tuple to make it immutable.
ID_SEQUENCE = (101, 102, 103, 104, 105, 106, 107, 108, 109, 110)

def get_value_at_index(index):
    """
    Retrieves the value from ID_SEQUENCE at a specified index.
    This function is secure because it performs bounds checking.

    Args:
        index (int): The index of the element to retrieve.

    Returns:
        int: The value at the specified index if the index is valid.
        None: If the index is out of bounds.
    """
    # Security check: Ensure the index is an integer and within valid bounds.
    if not isinstance(index, int):
        # Additional type safety
        return None
    if 0 <= index < len(ID_SEQUENCE):
        return ID_SEQUENCE[index]
    else:
        # Return None to indicate an invalid index was provided.
        return None

def main():
    """Main function to run test cases."""
    # 5 test cases
    test_indexes = [0, 9, 4, -1, 10]

    print("Running 5 test cases...")
    for i, index in enumerate(test_indexes):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Attempting to get value at index: {index}")
        value = get_value_at_index(index)
        if value is not None:
            print(f"Success! Value at index {index} is: {value}")
        else:
            print(f"Error: Index {index} is out of bounds or invalid.")

if __name__ == "__main__":
    main()