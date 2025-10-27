import sys

def convert_string_to_int(s):
    """
    Converts a string to an integer, handling potential errors.
    Returns a tuple (is_successful, value).
    """
    try:
        return True, int(s)
    except ValueError:
        return False, 0

def print_argument_at_index(argv):
    """
    Prints the command line argument at the index specified by the second argument.
    argv is a list of strings, like sys.argv.
    """
    # 1. Check if there are enough arguments (program name + index)
    if len(argv) < 2:
        print("Error: Not enough arguments. Usage: <program> <index> [arg1] [arg2] ...")
        return

    index_string = argv[1]
    
    # 2. Convert the second argument (at index 1) to an integer
    success, index = convert_string_to_int(index_string)

    if not success:
        print(f"Error: The second argument '{index_string}' must be a valid integer.")
        return

    # 3. Check if the calculated index is within the bounds of the argv list
    if 0 <= index < len(argv):
        # 4. Print the argument at the specified index
        print(argv[index])
    else:
        print(f"Error: Index {index} is out of bounds. Valid range is 0 to {len(argv) - 1}.")

def main():
    print("--- Running with actual command line arguments ---")
    # To test this part, run from command line:
    # python your_script_name.py 3 apple banana orange grape
    # Expected output: grape
    if len(sys.argv) > 1:
        print_argument_at_index(sys.argv)
    else:
        print("No command line arguments provided for live test.")

    print("\n--- Running with 5 test cases ---")

    # Test Case 1: Valid input
    print("Test 1: ", end="")
    test1 = ["program.py", "3", "zero", "one", "two", "three"]
    print_argument_at_index(test1) # Expected: one

    # Test Case 2: Index out of bounds (too high)
    print("Test 2: ", end="")
    test2 = ["program.py", "5", "a", "b", "c"]
    print_argument_at_index(test2) # Expected: Error: Index 5 is out of bounds.

    # Test Case 3: Index is not a number
    print("Test 3: ", end="")
    test3 = ["program.py", "two", "a", "b", "c"]
    print_argument_at_index(test3) # Expected: Error: The second argument 'two' must be a valid integer.

    # Test Case 4: Not enough arguments
    print("Test 4: ", end="")
    test4 = ["program.py"]
    print_argument_at_index(test4) # Expected: Error: Not enough arguments.

    # Test Case 5: Index is negative
    print("Test 5: ", end="")
    test5 = ["program.py", "-1", "a", "b"]
    print_argument_at_index(test5) # Expected: Error: Index -1 is out of bounds.

if __name__ == "__main__":
    main()