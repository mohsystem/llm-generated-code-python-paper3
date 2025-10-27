import sys

def get_argument_by_index(argv):
    """
    Retrieves the argument at the index specified by argv[1].

    Args:
        argv: A list of command-line arguments, typically from sys.argv.
              argv[0] is the program name, argv[1] should be the desired index.

    Returns:
        The argument at the specified index, or None if an error occurs.
    """
    # Rule #4: Validate input - check if enough arguments are provided.
    if len(argv) < 2:
        print("Error: Not enough arguments. Please provide an index.", file=sys.stderr)
        return None

    try:
        # Rule #4: Validate input type.
        index_str = argv[1]
        index = int(index_str)
        
        # Rule #1 & #4: Ensure the index is within the buffer's boundaries.
        if index < 0:
            print(f"Error: Index {index} cannot be negative.", file=sys.stderr)
            return None
        
        # Access the element, which will raise IndexError if out of bounds.
        # Rule #7: Handle exceptions for out-of-bounds access.
        value = argv[index]
        return value

    except ValueError:
        # Rule #7: Handle exceptions for invalid number formats.
        print(f"Error: The first argument '{argv[1]}' must be a valid integer index.", file=sys.stderr)
        return None
    except IndexError:
        # Rule #1 & #4: Boundary check failed.
        print(f"Error: Index {index} is out of bounds for {len(argv)} arguments.", file=sys.stderr)
        return None


def run_tests():
    """Runs a series of predefined test cases."""
    print("\n--- Running 5 test cases ---")

    # Test Case 1: Valid case
    print("\nTest Case 1: Valid index")
    test1 = ["program.py", "2", "first", "second"]
    print(f"Input: {test1}")
    result1 = get_argument_by_index(test1)
    print(f"Output: {result1}")

    # Test Case 2: Index out of bounds (too high)
    print("\nTest Case 2: Index out of bounds (high)")
    test2 = ["program.py", "5", "only", "three", "args"]
    print(f"Input: {test2}")
    result2 = get_argument_by_index(test2)
    print(f"Output: {result2}")

    # Test Case 3: Negative index
    print("\nTest Case 3: Negative index")
    test3 = ["program.py", "-1", "a", "b"]
    print(f"Input: {test3}")
    result3 = get_argument_by_index(test3)
    print(f"Output: {result3}")

    # Test Case 4: Invalid index format (not a number)
    print("\nTest Case 4: Invalid index format")
    test4 = ["program.py", "foo", "bar"]
    print(f"Input: {test4}")
    result4 = get_argument_by_index(test4)
    print(f"Output: {result4}")

    # Test Case 5: Not enough arguments
    print("\nTest Case 5: Not enough arguments")
    test5 = ["program.py"]
    print(f"Input: {test5}")
    result5 = get_argument_by_index(test5)
    print(f"Output: {result5}")

    print("\n--- Tests finished ---")


if __name__ == "__main__":
    print("--- Running with actual command line arguments ---")
    result = get_argument_by_index(sys.argv)
    if result is not None:
        print(f"Value at specified index: {result}")
    else:
        print("Failed to retrieve argument.")
    print("------------------------------------------------")
    
    run_tests()