import sys

OFFSET = 1000

def add_offset(value):
    """
    Adds a constant offset to the given value.

    Args:
        value: An integer or float.
    
    Returns:
        The value with the offset added.
    """
    return value + OFFSET

def main():
    """
    Main function to run the program and test cases.
    """
    # We can use the first command-line argument if provided.
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        print(f"Processing command-line argument: {arg}")
        try:
            # Python's int can handle arbitrarily large integers
            input_value = int(arg)
            result = add_offset(input_value)
            print(f"Input: {input_value}, Result: {result}")
        except ValueError:
            print(f"Error: Input '{arg}' is not a valid integer.", file=sys.stderr)
        print("\n--- Running Internal Test Cases ---")
    
    # 5 internal test cases for demonstration
    test_cases = [
        "25",           # Basic positive number
        "-1050",        # Basic negative number
        "0",            # Zero
        "1000000000000000000000000000000", # Very large number
        "xyz"           # Invalid input
    ]

    for test in test_cases:
        print(f"Processing test case: {test}")
        try:
            input_value = int(test)
            result = add_offset(input_value)
            print(f"Input: {input_value}, Result: {result}")
        except ValueError:
            print(f"Error: Input '{test}' is not a valid integer.", file=sys.stderr)

if __name__ == "__main__":
    main()