
import sys
from typing import Optional

MAX_INPUT_LENGTH = 100
MIN_INT_VALUE = -2147483648
MAX_INT_VALUE = 2147483647


def convert_to_integer(input_str: str) -> Optional[int]:
    """\n    Converts a string to an integer with validation.\n    \n    Args:\n        input_str: The string to convert\n        \n    Returns:\n        The converted integer or None if invalid\n    """
    if input_str is None:
        return None
    
    trimmed = input_str.strip()
    
    if not trimmed or len(trimmed) > MAX_INPUT_LENGTH:
        return None
    
    # Validate format: optional sign followed by digits
    if not all(c.isdigit() or (i == 0 and c in '+-') for i, c in enumerate(trimmed)):
        return None
    
    if trimmed in ('+', '-'):
        return None
    
    try:
        value = int(trimmed)
        
        if value < MIN_INT_VALUE or value > MAX_INT_VALUE:
            return None
        
        return value
    except (ValueError, OverflowError):
        return None


def main() -> None:
    """Main function with test cases and interactive input."""
    test_cases = [
        "42",
        "-123",
        "0",
        "2147483647",
        "invalid123"
    ]
    
    print("Running test cases:")
    for test_case in test_cases:
        result = convert_to_integer(test_case)
        print(f'Input: "{test_case}" -> Output: {result}')
    
    print("\\nEnter an integer to convert:")
    try:
        user_input = sys.stdin.readline()
        
        if user_input and len(user_input) <= MAX_INPUT_LENGTH + 1:  # +1 for newline
            result = convert_to_integer(user_input)
            if result is not None:
                print(f"Converted integer: {result}")
            else:
                print("Error: Invalid integer format")
        else:
            print("Error: Input exceeds maximum length")
    except (EOFError, KeyboardInterrupt):
        print("\\nInput interrupted")
    except Exception:
        print("Error reading input", file=sys.stderr)


if __name__ == "__main__":
    main()
