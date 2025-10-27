import sys

def add_thousand(input_str: str):
    """
    Converts a string to an integer and adds 1000 to it.
    Handles non-integer input gracefully. Python's integers handle arbitrary
    size, so overflow is not a concern for the addition itself.

    Args:
        input_str: The string representation of the number.

    Returns:
        The integer result if conversion is successful, otherwise None.
    """
    if not isinstance(input_str, str):
        print("Error: Input must be a string.", file=sys.stderr)
        return None
    try:
        number = int(input_str)
        return number + 1000
    except ValueError:
        print(f"Error: Invalid input '{input_str}'. Please provide a valid integer.", file=sys.stderr)
        return None

def run_tests():
    """Runs a series of test cases for the add_thousand function."""
    print("\n--- Running Test Cases ---")
    # Test cases: normal, zero, negative, large number, invalid string
    test_cases = ["10", "0", "-50", "9007199254740991", "not a number"]
    for test in test_cases:
        print(f'Test case: "{test}" -> ', end="")
        result = add_thousand(test)
        if result is not None:
            print(f"Result: {result}")
        else:
            print("Handled error as expected.")
    print("--- Test Cases Finished ---\n")

def main():
    """
    Main function to process command-line arguments or run tests.
    """
    if len(sys.argv) == 2:
        print(f"Processing command line argument: {sys.argv[1]}")
        result = add_thousand(sys.argv[1])
        if result is not None:
            print(f"Result: {result}")
        else:
            print("Failed to process command line argument.")
    else:
        print("Usage: python your_script_name.py <number>")
        print("No command line argument provided. Running test cases instead.")

    # Running 5 test cases as requested.
    run_tests()

if __name__ == "__main__":
    main()