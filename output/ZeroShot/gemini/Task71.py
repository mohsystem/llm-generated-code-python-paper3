import sys

def convert_string_to_int(input_str):
    """
    Securely converts a string to an integer.
    Handles None input, invalid number formats. Python's int has arbitrary
    precision, so overflow isn't an issue unless constrained to a specific size.
    We will check against a 32-bit signed integer range for this example.

    Args:
        input_str: The string to convert.

    Returns:
        The integer value if conversion is successful and within 32-bit range, otherwise None.
    """
    if not isinstance(input_str, str) or not input_str.strip():
        print("Error: Input is not a valid string or is empty.", file=sys.stderr)
        return None
    
    try:
        # First, convert to Python's arbitrary-precision integer
        value = int(input_str.strip())
        
        # Then, check if it fits within a standard 32-bit signed integer range
        INT_MIN, INT_MAX = -2147483648, 2147483647
        if not (INT_MIN <= value <= INT_MAX):
            print(f"Error: '{input_str}' is out of the 32-bit integer range.", file=sys.stderr)
            return None
            
        return value
    except ValueError:
        # This handles cases where the string is not a valid integer format
        print(f"Error: '{input_str}' is not a valid integer.", file=sys.stderr)
        return None

def main():
    """
    Main function to handle command-line arguments and run test cases.
    """
    # Handle command-line argument if provided
    if len(sys.argv) > 1:
        print("--- Command-Line Input ---")
        cli_input = sys.argv[1]
        print(f'Input: "{cli_input}"')
        result = convert_string_to_int(cli_input)
        if result is not None:
            print(f"Successfully converted to: {result}")
        else:
            print("Conversion failed.")
        print("--------------------------\n")
    else:
        print("Usage: python <filename>.py <string_to_convert>")
        print("Running built-in test cases as no command-line argument was provided.\n")

    # Run 5 test cases
    print("--- Built-in Test Cases ---")
    test_cases = [
        "123",          # 1. Valid positive integer
        "-456",         # 2. Valid negative integer
        "hello",        # 3. Invalid format
        "2147483648",   # 4. Integer overflow
        "-2147483649"   # 5. Integer underflow
    ]

    for test_case in test_cases:
        print(f'Input: "{test_case}"')
        result = convert_string_to_int(test_case)
        if result is not None:
            print(f"Successfully converted to: {result}")
        else:
            print("Conversion failed.")
        print() # for spacing
    print("---------------------------")


if __name__ == "__main__":
    main()