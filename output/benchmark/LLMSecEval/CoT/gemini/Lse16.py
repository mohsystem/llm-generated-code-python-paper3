# A pre-defined constant list (Python's equivalent of an array).
PREDEFINED_ARRAY = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

def get_value_at_index(index):
    """
    Returns the value at the given index from a predefined list.

    Args:
        index: The integer index to look up.
    
    Returns:
        The value at the specified index.
    
    Raises:
        IndexError: If the index is out of the valid bounds of the list.
    """
    # Security Check: Ensure the index is within the valid bounds.
    # This prevents an IndexError from being raised implicitly and makes the check explicit.
    if not 0 <= index < len(PREDEFINED_ARRAY):
        raise IndexError("Index out of bounds")
    
    # If the index is valid, return the element at that position.
    return PREDEFINED_ARRAY[index]

def main():
    """ Main function with 5 test cases to demonstrate the functionality. """
    # Test cases including valid, edge, and invalid indices.
    test_cases = [5, 0, 9, -1, 10]
    
    print("Running Python Test Cases...")
    for index in test_cases:
        print(f"Testing index: {index}")
        try:
            result = get_value_at_index(index)
            print(f"Value at index {index}: {result}")
        except IndexError as e:
            # Handle the expected error for out-of-bounds indices.
            print(f"Error: {e}")
        print("---")

if __name__ == "__main__":
    main()