import sys

def convert_to_integer(input_str: str):
    """
    Attempts to convert a string to an integer.
    This function is secure against invalid input by using a try-except block
    to handle ValueError, which is raised for invalid literals or numbers
    that are too large for the system's integer representation (on systems
    with fixed-size integers, though Python's are arbitrary precision).
    It also handles non-string inputs gracefully.

    Args:
        input_str: The string to be converted.

    Returns:
        The integer value if conversion is successful, otherwise None.
    """
    if not isinstance(input_str, str):
        return None
    try:
        # strip() removes leading/trailing whitespace
        return int(input_str.strip())
    except (ValueError, TypeError):
        # ValueError for invalid format e.g., "abc"
        # TypeError if input is not string-like
        return None

def main():
    """Main function with test cases."""
    test_cases = [
        "123",        # Valid positive integer
        "-456",       # Valid negative integer
        "  789  ",    # Valid integer with whitespace
        "abc",        # Invalid non-numeric string
        "9999999999999999999999999", # Very large number (Python handles this)
        "1.0"         # A float string, which int() with base 10 rejects
    ]

    print("Running Python Test Cases:")
    for test_case in test_cases:
        print(f'Input: "{test_case}" -> ', end="")
        result = convert_to_integer(test_case)
        if result is not None:
            print(f"Success, value: {result}")
        else:
            print("Failed to convert.")

if __name__ == "__main__":
    main()