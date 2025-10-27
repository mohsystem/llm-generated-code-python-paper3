import sys

# A predefined list of integers
_DATA = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index: int) -> int:
    """
    Returns the value from a predefined list at the given index.

    Args:
        index: The index of the element to retrieve.

    Returns:
        The integer value at the specified index.

    Raises:
        IndexError: If the index is out of the valid range.
        TypeError: If the index is not an integer.
    """
    # Rule #4: Validate input type
    if not isinstance(index, int):
        raise TypeError("Index must be an integer.")

    # Rule #1, #4: Validate the index to ensure it is within the list's boundaries.
    if not (0 <= index < len(_DATA)):
        # Rule #8: Fail closed with a clear error.
        raise IndexError(f"Index {index} is out of bounds for list of size {len(_DATA)}")

    return _DATA[index]

def main():
    """Main function with test cases."""
    # 5 test cases
    test_indexes = [0, 5, 9, -1, 10]

    for index in test_indexes:
        try:
            # Rule #7: Ensure all exceptions are caught and handled appropriately.
            value = get_value_at_index(index)
            print(f"Value at index {index}: {value}")
        except (IndexError, TypeError) as e:
            # Rule #8: Do not leak internal details in error messages to the user.
            print(f"Error for index {index}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()