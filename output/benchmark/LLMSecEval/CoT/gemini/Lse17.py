import sys

def get_value_at_index(arr, index):
    """
    Returns the value at a specific index in a list.
    Performs bounds checking to prevent IndexError.

    Args:
        arr: The source list of numbers.
        index: The index of the element to retrieve.
    Returns:
        The value at the specified index, or None if the index is out of bounds.
    """
    # Security: Validate the index to ensure it is within the valid bounds.
    # This prevents IndexError and protects against potential vulnerabilities
    # that could arise from out-of-bounds access.
    if not isinstance(index, int) or not (0 <= index < len(arr)):
        print(f"Error: Index {index} is out of bounds.", file=sys.stderr)
        return None  # Return None to indicate an error.
    return arr[index]

def main():
    """Main function with 5 test cases."""
    data = [10, 20, 30, 40, 50, 60, 70]

    # --- 5 Test Cases ---

    # Test Case 1: Valid index in the middle
    index1 = 3
    value1 = get_value_at_index(data, index1)
    if value1 is not None:
        print(f"Test 1: Value at index {index1} is {value1}")

    # Test Case 2: Valid index at the beginning
    index2 = 0
    value2 = get_value_at_index(data, index2)
    if value2 is not None:
        print(f"Test 2: Value at index {index2} is {value2}")

    # Test Case 3: Valid index at the end
    index3 = len(data) - 1
    value3 = get_value_at_index(data, index3)
    if value3 is not None:
        print(f"Test 3: Value at index {index3} is {value3}")

    # Test Case 4: Invalid index (negative)
    index4 = -1
    print("Test 4: ", end="")
    get_value_at_index(data, index4)

    # Test Case 5: Invalid index (too large)
    index5 = 10
    print("Test 5: ", end="")
    get_value_at_index(data, index5)

if __name__ == "__main__":
    main()