def get_value_from_array(arr, size, index):
    """
    Gets the value from an array at a specified index.

    Args:
        arr: The source list of integers.
        size: The size of the list.
        index: The index of the element to retrieve.

    Returns:
        The integer value at the given index.

    Raises:
        IndexError: if the index is out of the valid range [0, size-1].
    """
    # Security check: Ensure the index is within the valid bounds of the array.
    if not 0 <= index < size:
        raise IndexError(f"Error: Index {index} is out of bounds for array size {size}")
    return arr[index]

def main():
    """Main function with test cases."""
    test_array = [10, 20, 30, 40, 50]
    size = len(test_array)

    # Test cases
    test_indexes = [2, 0, 4, -1, 5]

    print("Running Python Test Cases...")
    for i, index_to_test in enumerate(test_indexes):
        print(f"Test Case {i + 1}: Trying to get value at index {index_to_test}")
        try:
            value = get_value_from_array(test_array, size, index_to_test)
            print(f"  Success: Value is {value}")
        except IndexError as e:
            print(f"  Caught expected exception: {e}")

if __name__ == "__main__":
    main()