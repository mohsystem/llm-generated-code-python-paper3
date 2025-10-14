import sys
from typing import Optional

def convert_string_to_integer(input_str: Optional[str]) -> None:
    """
    Attempts to convert a string to an integer and prints the result or an error.

    This function handles non-string/None input, empty strings, and strings
    that do not represent a valid integer by catching ValueError. It also
    strips leading/trailing whitespace before conversion.

    Args:
        input_str: The string to be converted.
    """
    if not isinstance(input_str, str):
        print(f"Input: {input_str} -> Error: Input must be a string.")
        return

    # Strip leading/trailing whitespace
    s_trimmed = input_str.strip()

    if not s_trimmed:
        print(f"Input: \"{input_str}\" -> Error: Input is empty or only contains whitespace.")
        return

    try:
        result = int(s_trimmed)
        print(f"Input: \"{input_str}\" -> Success: {result}")
    except ValueError:
        print(f"Input: \"{input_str}\" -> Error: Not a valid integer.")

def main() -> None:
    """
    Main function to run test cases for the string-to-integer conversion.
    """
    test_cases = [
        "42",           # Valid integer
        "  -100  ",     # Valid integer with whitespace
        "0",            # Valid zero
        "hello world",  # Invalid characters
        "3.14"          # Not an integer
    ]

    print("--- Running 5 Test Cases ---")
    for test in test_cases:
        convert_string_to_integer(test)
    print("--- Test Cases Finished ---")

if __name__ == "__main__":
    main()