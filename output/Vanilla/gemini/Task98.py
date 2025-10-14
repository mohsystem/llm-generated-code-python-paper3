def attempt_conversion(input_str):
    """
    Attempts to convert a given string to an integer and prints the outcome.
    """
    try:
        # The int() function in Python automatically handles leading/trailing whitespace.
        number = int(input_str)
        print(f'Input: "{input_str}" -> Success! Converted to integer: {number}')
    except ValueError:
        print(f'Input: "{input_str}" -> Failed. Not a valid integer.')

def main():
    """
    Main function to run 5 test cases.
    """
    # List of 5 test cases to demonstrate the functionality.
    test_cases = [
        "123",      # Valid positive integer
        "-45",      # Valid negative integer
        "  99  ",   # Valid integer with whitespace
        "abc",      # Invalid string
        "12a34"     # Invalid string with mixed characters
    ]

    print("--- Python: Testing Integer Conversion ---")
    for test in test_cases:
        attempt_conversion(test)

if __name__ == "__main__":
    main()