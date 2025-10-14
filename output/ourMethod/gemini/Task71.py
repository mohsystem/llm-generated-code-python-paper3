import sys
from typing import Optional

def convert_string_to_int(s: str) -> Optional[int]:
    """
    Attempts to convert a string to an integer.

    Args:
        s: The string to convert.

    Returns:
        The integer value if conversion is successful, otherwise None.
    """
    try:
        return int(s)
    except ValueError:
        return None

def main():
    """
    Main function to handle command-line arguments or run test cases.
    """
    if len(sys.argv) > 1:
        print("Processing command line argument:")
        input_str = sys.argv[1]
        result = convert_string_to_int(input_str)
        if result is not None:
            print(f"Successfully converted \"{input_str}\" to {result}")
        else:
            print(f"Error: Could not convert \"{input_str}\" to an integer.")
    else:
        print("No command line arguments provided. Running test cases:")
        test_cases = [
            "123",       # Valid positive integer
            "-456",      # Valid negative integer
            "0",         # Valid zero
            "abc",       # Invalid format
            "99999999999999999999999999999" # Valid large integer in Python
        ]
        for test in test_cases:
            result = convert_string_to_int(test)
            if result is not None:
                print(f"Input: \"{test}\", Output: {result}")
            else:
                print(f"Input: \"{test}\", Error: Invalid number format.")

if __name__ == "__main__":
    main()