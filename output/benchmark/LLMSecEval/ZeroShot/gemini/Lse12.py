import sys

def get_value_from_array(arr, size, index):
    """
    Gets a value from a list/array at a specified index.
    Securely checks if the index is within the valid bounds.
    
    Args:
        arr: The source list of integers.
        size: The size of the list.
        index: The index from which to retrieve the value.
        
    Returns:
        The value at the given index, or -1 if the index is out of bounds.
    """
    # Secure: Validate that the list is not None and the index is within bounds.
    # This prevents TypeError and IndexError.
    if arr is None or not 0 <= index < size:
        print(f"Error: Index {index} is out of bounds for array of size {size}.", file=sys.stderr)
        return -1  # Return a designated error code.
    return arr[index]

def main():
    """Main function to run test cases."""
    data = [10, 20, 30, 40, 50]
    size = len(data)

    print("Running 5 test cases...")

    # Test Case 1: Valid index in the middle
    index1 = 2
    print(f"\nTest Case 1: index = {index1}")
    value1 = get_value_from_array(data, size, index1)
    print(f"Value returned: {value1}")  # Expected: 30

    # Test Case 2: Valid index at the beginning
    index2 = 0
    print(f"\nTest Case 2: index = {index2}")
    value2 = get_value_from_array(data, size, index2)
    print(f"Value returned: {value2}")  # Expected: 10

    # Test Case 3: Invalid negative index
    index3 = -1
    print(f"\nTest Case 3: index = {index3}")
    value3 = get_value_from_array(data, size, index3)
    print(f"Value returned: {value3}")  # Expected: -1

    # Test Case 4: Invalid index equal to size
    index4 = size
    print(f"\nTest Case 4: index = {index4}")
    value4 = get_value_from_array(data, size, index4)
    print(f"Value returned: {value4}")  # Expected: -1

    # Test Case 5: Valid index at the end
    index5 = 4
    print(f"\nTest Case 5: index = {index5}")
    value5 = get_value_from_array(data, size, index5)
    print(f"Value returned: {value5}")  # Expected: 50

if __name__ == "__main__":
    main()