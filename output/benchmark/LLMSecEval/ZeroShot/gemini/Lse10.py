import sys

def get_value_from_array(arr, size, index):
    """
    Securely retrieves a value from a list by performing bounds checking.

    Args:
        arr: The list of integers.
        size: The size of the list.
        index: The index of the element to retrieve.

    Returns:
        The value at the given index, or -1 if the index is out of bounds.
    """
    # Secure: Check if the index is within the valid bounds of the array.
    if 0 <= index < size:
        return arr[index]
    else:
        # Return an error code for out-of-bounds access.
        return -1

def main():
    """ Main function to run test cases. """
    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)

    print("--- 5 Test Cases ---")

    # Test Case 1: Valid index in the middle
    index1 = 2
    value1 = get_value_from_array(id_sequence, size, index1)
    print(f"Index {index1} -> Value: {value1}")  # Expected: 30

    # Test Case 2: Valid boundary index (first element)
    index2 = 0
    value2 = get_value_from_array(id_sequence, size, index2)
    print(f"Index {index2} -> Value: {value2}")  # Expected: 10

    # Test Case 3: Valid boundary index (last element)
    index3 = 4
    value3 = get_value_from_array(id_sequence, size, index3)
    print(f"Index {index3} -> Value: {value3}")  # Expected: 50

    # Test Case 4: Invalid negative index
    index4 = -1
    value4 = get_value_from_array(id_sequence, size, index4)
    print(f"Index {index4} -> Value: {value4}")  # Expected: -1

    # Test Case 5: Invalid out-of-bounds index
    index5 = 5
    value5 = get_value_from_array(id_sequence, size, index5)
    print(f"Index {index5} -> Value: {value5}")  # Expected: -1

    # As per the prompt, in a real application that reads one value,
    # the main block would look like this:
    #
    # input_index = int(sys.stdin.readline())
    # exit_code = get_value_from_array(id_sequence, size, input_index)
    # sys.exit(exit_code)

if __name__ == "__main__":
    main()