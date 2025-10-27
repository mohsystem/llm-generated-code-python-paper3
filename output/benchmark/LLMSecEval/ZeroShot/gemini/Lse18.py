def get_value_at_index(arr, index):
    """
    Securely gets the value at a specified index of a list.

    Args:
        arr: The list to access.
        index: The index of the element to retrieve.

    Returns:
        The value at the specified index.

    Raises:
        TypeError: If the input 'arr' is not a list.
        IndexError: If the index is out of the valid range.
    """
    if not isinstance(arr, list):
        raise TypeError("Input 'arr' must be a list.")
    
    # Secure: Check if the index is within the valid range.
    if not 0 <= index < len(arr):
        raise IndexError(f"Index {index} is out of bounds for list of size {len(arr)}")
        
    return arr[index]

def main():
    """Main function with test cases."""
    data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    print(f"Array: {data}")

    # Test Cases
    test_indexes = [5, 0, 9, -1, 10]

    for index in test_indexes:
        try:
            value = get_value_at_index(data, index)
            print(f"Test case index: {index} -> Success! Value: {value}")
        except (IndexError, TypeError) as e:
            print(f"Test case index: {index} -> Caught expected exception: {e}")

if __name__ == "__main__":
    main()