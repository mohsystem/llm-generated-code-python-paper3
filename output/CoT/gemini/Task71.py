import sys

def convert_string_to_int(input_str):
    """
    Attempts to convert a string to an integer.
    Handles None, empty, and non-numeric strings.

    Args:
        input_str: The string to be converted.

    Returns:
        An integer if conversion is successful, otherwise None.
    """
    if not isinstance(input_str, str):
        return None
    
    # Python's int() handles leading/trailing whitespace automatically.
    # It also handles arbitrarily large integers, so we don't need to check
    # for overflow in the same way as in C or Java for their fixed-size ints.
    try:
        return int(input_str)
    except (ValueError, TypeError):
        # ValueError for invalid formats like "abc"
        # TypeError for non-string inputs that might slip through
        return None

def main():
    # Section 1: Process command-line argument if provided
    if len(sys.argv) > 1:
        print("--- Processing Command-Line Argument ---")
        cli_input = sys.argv[1]
        print(f"Input: \"{cli_input}\"")
        result = convert_string_to_int(cli_input)
        if result is not None:
            print(f"Successfully converted to: {result}")
        else:
            print("Error: Conversion failed. Input is not a valid integer.")
        print("--------------------------------------\n")
    else:
        print("--- No Command-Line Argument Provided ---\n")

    # Section 2: Run 5 hardcoded test cases
    print("--- Running Hardcoded Test Cases ---")
    test_cases = [
        "456",          # Valid integer
        "-78",          # Valid negative integer
        "hello",        # Invalid format
        "99.9",         # Invalid format (float)
        "  101  "       # Valid with whitespace
    ]

    for i, test_input in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"Input: \"{test_input}\"")
        result = convert_string_to_int(test_input)
        if result is not None:
            print(f"Successfully converted to: {result}")
        else:
            print("Error: Conversion failed. Input is not a valid integer.")
        print()  # For spacing
    print("------------------------------------")

if __name__ == '__main__':
    main()