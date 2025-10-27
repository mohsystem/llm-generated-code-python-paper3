def get_value_at_index(arr, index):
    """
    Returns the value at the specified index in the list.
    Performs bounds checking to prevent security vulnerabilities.

    Args:
        arr: The source list.
        index: The index of the element to retrieve.

    Returns:
        The value at the specified index.

    Raises:
        IndexError: If the index is out of range.
    """
    # Security: Check if the index is within the valid bounds of the list.
    if not 0 <= index < len(arr):
        # Raising an exception is the standard Pythonic way to handle this error.
        raise IndexError(f"Index {index} is out of bounds for list of size {len(arr)}")
    
    return arr[index]

if __name__ == "__main__":
    data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    
    # 5 Test Cases
    test_indexes = [3, 0, 9, -1, 10]

    for index in test_indexes:
        try:
            value = get_value_at_index(data, index)
            print(f"Test Case - Index: {index}")
            print(f"Value at index {index} is: {value}")
        except IndexError as e:
            print(f"Test Case - Index: {index}")
            print(f"Error: {e}")
        print("--------------------")