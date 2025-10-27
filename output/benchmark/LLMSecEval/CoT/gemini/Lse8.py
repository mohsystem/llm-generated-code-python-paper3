import sys

def get_value_at_index(argv):
    """
    Retrieves the command-line argument at the index specified by the first argument.

    Args:
        argv: The list of command-line arguments from sys.argv.
              argv[0] is the script name, argv[1] should be the index.

    Returns:
        The argument at the specified index, or None if an error occurs.
    """
    # Security Check 1: Ensure there are enough arguments.
    # We need at least argv[1] (the index).
    if len(argv) < 2:
        print("Error: Not enough arguments. Usage: python your_script.py <index> <arg1> ...", file=sys.stderr)
        return None

    try:
        # Security Check 2: Safely parse the index from string to integer.
        index_str = argv[1]
        index = int(index_str)
    except ValueError:
        print(f"Error: The first argument ('{index_str}') must be a valid integer.", file=sys.stderr)
        return None

    # Security Check 3: Perform bounds checking on the arguments list.
    if not (0 <= index < len(argv)):
        print(f"Error: Index {index} is out of bounds. Valid range is [0, {len(argv) - 1}].", file=sys.stderr)
        return None

    # If all checks pass, return the value.
    return argv[index]

def main():
    """ Main function to run the logic and demonstrate test cases. """
    result = get_value_at_index(sys.argv)
    if result is not None:
        print(f"Value at index {sys.argv[1]}: {result}")

    # --- Test Cases ---
    # This script must be run from the command line to pass arguments.
    #
    # Test Case 1: Successful retrieval
    # Command: python your_script.py 3 apple banana orange grape
    # Expected Output: Value at index 3: orange
    #
    # Test Case 2: Index points to the script name itself (index 0)
    # Command: python your_script.py 0 test one two
    # Expected Output: Value at index 0: your_script.py
    #
    # Test Case 3: Error - Index out of bounds
    # Command: python your_script.py 5 apple banana
    # Expected Output: Error: Index 5 is out of bounds. Valid range is [0, 3].
    #
    # Test Case 4: Error - Invalid index format
    # Command: python your_script.py two apple banana
    # Expected Output: Error: The first argument ('two') must be a valid integer.
    #
    # Test Case 5: Error - Not enough arguments
    # Command: python your_script.py
    # Expected Output: Error: Not enough arguments. Usage: python your_script.py <index> <arg1> ...

if __name__ == "__main__":
    main()