import sys

def getValueFromArray(arr, size, index):
    """
    Gets a value from a list at a specific index with bounds checking.
    The function prevents out-of-bounds access by validating the index.

    :param arr: The source list of integers.
    :param size: The size of the list.
    :param index: The index of the element to retrieve.
    :return: The value at the given index, or 1 as an error code if the index is out of bounds.
    """
    # Security: Check if the index is within the valid bounds of the list (0 to size-1).
    # This prevents IndexError.
    if not 0 <= index < size:
        print(f"Error: Index {index} is out of bounds for list size {size}.", file=sys.stderr)
        return 1  # Return an error code for out-of-bounds access.
    return arr[index]

def main():
    """
    Main function to demonstrate getValueFromArray with 5 test cases.
    The original prompt required reading a single value and exiting with the result code.
    To show 5 test cases in a single run, this main function simulates those runs
    and prints what the result/exit code would be.
    """
    id_sequence = [10, 20, 30, 40, 50]
    size = len(id_sequence)

    # 5 Test Cases to demonstrate the functionality and security checks.
    test_indices = [
        0,  # Test Case 1: Valid index at the beginning
        2,  # Test Case 2: Valid index in the middle
        4,  # Test Case 3: Valid index at the end
        -1, # Test Case 4: Invalid index (negative)
        5   # Test Case 5: Invalid index (out of bounds high)
    ]
    
    print(f"Running 5 test cases for id_sequence: {id_sequence}")
    print("------------------------------------------")

    for i, index in enumerate(test_indices):
        print(f"Test Case {i + 1}: Requesting index {index}")
        
        result = getValueFromArray(id_sequence, size, index)
        
        print(f" -> Function returned: {result}")
        if result == 1 and not (0 <= index < size):
            print("   (This would be an exit code indicating an error)")
        else:
            print(f"   (Value at index {index} is {result}. This would be the exit code)")
        print("------------------------------------------")

if __name__ == "__main__":
    main()