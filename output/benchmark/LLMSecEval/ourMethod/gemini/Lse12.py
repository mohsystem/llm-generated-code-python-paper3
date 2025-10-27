import sys

def get_value_from_array(arr, size, index):
    """
    Returns the value at a given index in a list.
    Performs bounds checking to prevent out-of-bounds access.

    Args:
        arr: The list of integers.
        size: The size of the list.
        index: The index of the element to retrieve.

    Returns:
        The value at the specified index.

    Raises:
        IndexError: if the index is out of bounds.
    """
    # Rule #1, #4: Validate inputs and check boundaries
    if not (0 <= index < size):
        raise IndexError("Index is out of bounds.")
    return arr[index]

def run_test_case(arr, size, index, expected):
    """ Helper function to run a single test case. """
    sys.stdout.write(f"Test case: index={index}. ")
    try:
        result = get_value_from_array(arr, size, index)
        if result == expected:
            sys.stdout.write(f"Result: {result}. PASS\n")
        else:
            sys.stdout.write(f"Result: {result}. FAIL (Expected: {expected})\n")
    except IndexError:
        if expected == "exception":
            sys.stdout.write("Caught expected exception. PASS\n")
        else:
            sys.stdout.write("Caught unexpected exception. FAIL\n")

def main():
    """
    Main function to read an index and return the array value as exit code.
    """
    data = [10, 20, 30, 40, 50]
    data_size = len(data)

    # --- Test Cases ---
    print("--- Running Test Cases ---")
    run_test_case(data, data_size, 0, 10)
    run_test_case(data, data_size, 4, 50)
    run_test_case(data, data_size, 2, 30)
    run_test_case(data, data_size, -1, "exception")
    run_test_case(data, data_size, 5, "exception")
    print("--- Test Cases Finished ---\n")

    exit_code = 1  # Default error exit code
    
    print("Enter an index to retrieve a value from the array:")
    # Rule #7: Use try-except to handle potential errors
    try:
        line = sys.stdin.readline()
        # Rule #4: Validate that input is not empty
        if not line:
            raise ValueError("Empty input received.")
        
        index_str = line.strip()
        index = int(index_str)
        
        value = get_value_from_array(data, data_size, index)
        print(f"Value at index {index} is {value}")
        exit_code = value

    except ValueError:
        # Rule #4: Handle invalid input type
        sys.stderr.write("Error: Invalid input. Please enter an integer.\n")
        exit_code = 1
    except IndexError as e:
        sys.stderr.write(f"Error: {e}\n")
        exit_code = 1
    
    sys.exit(exit_code)

if __name__ == "__main__":
    main()