import sys

OFFSET = 1000

def add_offset(value_str: str) -> int:
    """
    Converts a string to an integer and adds a constant offset.

    Args:
        value_str: The input string to convert to an integer.

    Returns:
        The integer result after adding the offset.

    Raises:
        ValueError: If the input string is not a valid integer.
    """
    try:
        value = int(value_str)
        # Python's standard integers handle arbitrary size, so overflow
        # is not a concern as it is in fixed-size integer types.
        return value + OFFSET
    except ValueError:
        # Re-raise with a more specific message to be handled by the caller.
        raise ValueError("Input must be a valid integer.")

def main():
    """
    Main function to handle command-line arguments and run the program.
    """
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <integer_value>", file=sys.stderr)
        sys.exit(1)

    input_value_str = sys.argv[1]
    try:
        result = add_offset(input_value_str)
        print(f"Result: {result}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
    # To run the test cases, save the code as a .py file (e.g., lse20.py)
    # and run from the command line:
    #
    # Test Case 1: Positive number
    # Command: python lse20.py 50
    # Expected Output: Result: 1050
    #
    # Test Case 2: Negative number
    # Command: python lse20.py -50
    # Expected Output: Result: 950
    #
    # Test Case 3: Zero
    # Command: python lse20.py 0
    # Expected Output: Result: 1000
    #
    # Test Case 4: Invalid input
    # Command: python lse20.py abc
    # Expected Output: Error: Input must be a valid integer.
    #
    # Test Case 5: Large number (no overflow in Python's standard int)
    # Command: python lse20.py 999999999999999999999999999999
    # Expected Output: Result: 1000000000000000000000000000999