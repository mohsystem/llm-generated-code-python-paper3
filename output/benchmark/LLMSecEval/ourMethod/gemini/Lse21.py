import sys

def add_thousand(value_str):
    """
    Parses a string to an integer and adds 1000.
    
    Args:
        value_str: The string representation of the number.

    Returns:
        The integer result of the addition.

    Raises:
        ValueError: If the input string is not a valid integer.
    """
    try:
        # Python integers have arbitrary precision, so overflow on addition
        # is not a concern as it is in fixed-size integer languages.
        value = int(value_str)
        return value + 1000
    except ValueError:
        raise ValueError("Input must be a valid integer.")

def run_tests():
    """Runs a set of test cases."""
    print("--- Running Test Cases ---")
    test_cases = [
        "10",                      # Valid positive
        "0",                       # Valid zero
        "-50",                     # Valid negative
        "not a number",            # Invalid format
        "999999999999999999999999999999" # Large number
    ]
    for test in test_cases:
        try:
            result = add_thousand(test)
            print(f"Input: \"{test}\", Output: {result}")
        except ValueError as e:
            print(f"Input: \"{test}\", Error: {e}")

def main():
    """
    Main entry point of the script.
    Processes a command-line argument or runs tests.
    """
    if len(sys.argv) == 2:
        try:
            result = add_thousand(sys.argv[1])
            print(result)
            return 0  # Success
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1  # Failure
    elif len(sys.argv) == 1:
        run_tests()
        return 0 # Tests ran successfully
    else:
        print(f"Usage: python {sys.argv[0]} <integer>", file=sys.stderr)
        return 1 # Failure

if __name__ == "__main__":
    sys.exit(main())