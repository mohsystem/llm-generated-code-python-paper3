import sys

def add_thousand(input_str):
    """
    Converts a string to an integer and adds 1000.
    Raises ValueError if the string is not a valid integer.
    
    Args:
        input_str: The string to be converted to a number.
        
    Returns:
        The number plus 1000.
        
    Raises:
        ValueError: If input_str cannot be converted to an integer.
    """
    number = int(input_str)
    return number + 1000

def main():
    """
    Main function to handle command-line arguments and run test cases.
    """
    # --- 1. Process Command Line Argument ---
    # sys.argv[0] is the script name, so we expect len(sys.argv) to be 2
    if len(sys.argv) != 2:
        print("Usage: python your_script_name.py <number>", file=sys.stderr)
        print("Note: Exactly one command-line argument is required.", file=sys.stderr)
    else:
        try:
            input_arg = sys.argv[1]
            result = add_thousand(input_arg)
            print(f"Result from command line input '{input_arg}': {result}")
        except ValueError:
            print(f"Error: The provided command-line argument '{sys.argv[1]}' is not a valid number.", file=sys.stderr)

    # --- 2. Run 5 Test Cases ---
    print("\n--- Running 5 Internal Test Cases ---")
    test_inputs = ["10", "-10", "0", "99999999999999999999", "xyz"]
    for i, test_input in enumerate(test_inputs, 1):
        print(f"\nTest Case {i}: Input = \"{test_input}\"")
        try:
            test_result = add_thousand(test_input)
            print(f"  Output: {test_result}")
        except ValueError:
            print("  Output: Error - Invalid number format.", file=sys.stderr)

if __name__ == "__main__":
    main()