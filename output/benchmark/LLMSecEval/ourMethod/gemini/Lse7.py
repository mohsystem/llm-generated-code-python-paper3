import sys

def get_argument_at_index(argv):
    """
    Retrieves an argument from a list at an index specified by another argument.
    In Python, sys.argv[0] is the script name. We follow the C-style convention
    where the second program argument (argv[1]) specifies the index.

    Args:
        argv: A list of string arguments, typically sys.argv.

    Returns:
        The argument at the specified index, or an error message string.
    """
    # Rule #4: Validate input - ensure there are enough arguments
    # We need at least the script name and an index argument.
    if len(argv) < 2:
        return "Error: Insufficient arguments. At least two are required."

    index_str = argv[1]
    try:
        # Rule #4: Validate input format
        index = int(index_str)
    except ValueError:
        return f"Error: The second argument '{index_str}' must be a valid integer."

    # Rule #1, #2: Ensure the index is within the buffer's boundaries
    if not (0 <= index < len(argv)):
        return f"Error: Index {index} is out of bounds for the arguments list (size: {len(argv)})."

    return argv[index]

def main():
    """Main function to run the program and demonstrate test cases."""
    # Process command-line arguments if provided
    # The first element of sys.argv is the script name itself
    if len(sys.argv) > 1:
        print("--- Processing Command Line Arguments ---")
        print(f"Input: {sys.argv}")
        print(f"Output: {get_argument_at_index(sys.argv)}")
        print("----------------------------------------\n")

    print("--- Running Built-in Test Cases ---")

    # Test Case 1: Valid index
    test1 = ["./script.py", "2", "target_arg", "arg3"]
    print("\nTest Case 1: Valid index")
    print(f"Input: {test1}")
    print(f"Output: {get_argument_at_index(test1)}")

    # Test Case 2: Index pointing to the script name
    test2 = ["./script.py", "0", "arg2"]
    print("\nTest Case 2: Index points to script name")
    print(f"Input: {test2}")
    print(f"Output: {get_argument_at_index(test2)}")

    # Test Case 3: Index out of bounds (too high)
    test3 = ["./script.py", "3"]
    print("\nTest Case 3: Index out of bounds (high)")
    print(f"Input: {test3}")
    print(f"Output: {get_argument_at_index(test3)}")

    # Test Case 4: Invalid index format (not an integer)
    test4 = ["./script.py", "two", "arg2"]
    print("\nTest Case 4: Invalid index format")
    print(f"Input: {test4}")
    print(f"Output: {get_argument_at_index(test4)}")

    # Test Case 5: Insufficient arguments
    test5 = ["./script.py"]
    print("\nTest Case 5: Insufficient arguments")
    print(f"Input: {test5}")
    print(f"Output: {get_argument_at_index(test5)}")

if __name__ == "__main__":
    main()