
import sys
import re
from typing import Optional


def convert_to_integer(input_str: Optional[str]) -> int:
    """\n    Converts a string to an integer with validation.\n    \n    Args:\n        input_str: The string to convert\n        \n    Returns:\n        The converted integer\n        \n    Raises:\n        ValueError: If input is invalid\n    """
    # Validate input is not None or empty
    if input_str is None or not input_str.strip():
        raise ValueError("Input cannot be None or empty")
    
    # Sanitize input - remove leading/trailing whitespace
    sanitized = input_str.strip()
    
    # Validate length to prevent potential issues
    if len(sanitized) > 15:
        raise ValueError("Input length exceeds maximum allowed")
    
    # Validate characters - only allow digits, optional leading sign
    if not re.match(r'^[+-]?\\d+$', sanitized):
        raise ValueError("Input contains invalid characters. Only digits and optional leading +/- allowed")
    
    try:
        # Parse the integer
        value = int(sanitized)
        
        # Check if value is within 32-bit signed integer range
        if value < -2147483648 or value > 2147483647:
            raise ValueError("Value out of integer range")
        
        return value
    except ValueError as e:
        if "invalid literal" in str(e):
            raise ValueError(f"Invalid number format: {e}")
        raise


def main():
    """Main function with test cases."""
    test_cases = ["123", "-456", "0", "2147483647", "invalid123"]
    
    # Check if command line arguments provided
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            try:
                result = convert_to_integer(arg)
                print(f"Input: '{arg}' -> Result: {result}")
            except ValueError as e:
                print(f"Error for input '{arg}': {e}", file=sys.stderr)
    else:
        # Run test cases
        print("Running test cases:")
        for test in test_cases:
            try:
                result = convert_to_integer(test)
                print(f"Input: '{test}' -> Result: {result}")
            except ValueError as e:
                print(f"Error for input '{test}': {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
