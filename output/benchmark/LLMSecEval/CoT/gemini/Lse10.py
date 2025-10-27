import sys

def get_value_from_array(arr, size, index):
    """
    Returns the value at a given index in an array.
    Performs bounds checking to prevent out-of-bounds access.

    Args:
        arr: The list/array of integers.
        size: The size of the array.
        index: The index of the element to retrieve.
    
    Returns:
        The value at the specified index, or -1 if the index is out of bounds.
    """
    # Security: Check if the index is within the valid bounds of the array.
    if 0 <= index < size:
        return arr[index]
    # Return an error code for invalid index.
    return -1

def main():
    """
    Main function to read an index, get a value from a predefined array,
    and return it as the program's exit code.
    """
    id_sequence = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    size = len(id_sequence)
    index = 0

    print("Enter an integer index:")
    try:
        # Security: Ensure the input can be converted to an integer.
        input_str = sys.stdin.readline()
        index = int(input_str)
    except (ValueError, TypeError):
        sys.stderr.write("Error: Invalid input. Please enter an integer.\n")
        sys.exit(1) # Exit with a general error code for bad input.

    result = get_value_from_array(id_sequence, size, index)

    if result == -1:
        sys.stderr.write("Error: Index out of bounds.\n")
        sys.exit(1) # Exit with a general error code for out-of-bounds access.
    else:
        # Exit with the value from the array as the exit code.
        # Note: Exit codes are typically 0-255. Larger values may be truncated.
        print(f"Value at index {index} is {result}. Exiting with this value.")
        sys.exit(result)

if __name__ == "__main__":
    main()

# Main method test cases:
# 1. Input: 2
#    Expected Output: Program exits with code 30. (Value at index 2 is 30)
# 2. Input: 0
#    Expected Output: Program exits with code 10. (Value at index 0 is 10)
# 3. Input: 9
#    Expected Output: Program exits with code 100. (Value at index 9 is 100)
# 4. Input: -1
#    Expected Output: Prints "Error: Index out of bounds." and exits with code 1.
# 5. Input: 10
#    Expected Output: Prints "Error: Index out of bounds." and exits with code 1.