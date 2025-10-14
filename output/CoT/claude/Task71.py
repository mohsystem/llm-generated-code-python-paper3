
import sys

def convert_to_integer(input_str):
    """\n    Safely converts a string to an integer with proper error handling\n    \n    Args:\n        input_str: The string to convert\n        \n    Returns:\n        The converted integer, or None if conversion fails\n    """
    # Input validation
    if input_str is None or not isinstance(input_str, str) or not input_str.strip():
        print("Error: Input is None, not a string, or empty", file=sys.stderr)
        return None
    
    try:
        # Trim whitespace and attempt conversion
        trimmed_input = input_str.strip()
        
        # Convert to integer
        result = int(trimmed_input)
        
        # Python handles arbitrary precision, but check for typical int32 range
        if result > 2147483647 or result < -2147483648:
            print(f"Warning: Value outside typical 32-bit integer range: {trimmed_input}", file=sys.stderr)
        
        return result
        
    except ValueError as e:
        print(f"Error: Invalid integer format: '{input_str}'", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error: Unexpected error during conversion: {e}", file=sys.stderr)
        return None


def main():
    # Security: Validate command line arguments exist
    if len(sys.argv) < 2:
        print("Error: No command line arguments provided", file=sys.stderr)
        print("Usage: python Task71.py <integer_string>")
        return
    
    print("=== Command Line Argument Conversion ===")
    for i, arg in enumerate(sys.argv[1:], 1):
        print(f"\\nArgument {i}: {arg}")
        result = convert_to_integer(arg)
        if result is not None:
            print(f"Converted successfully: {result}")
    
    # Test cases
    print("\\n=== Running Test Cases ===")
    test_cases = [
        "42",                    # Valid positive integer
        "-123",                  # Valid negative integer
        "0",                     # Zero
        "2147483647",           # MAX_VALUE for int32
        "invalid123",           # Invalid format
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\\nTest Case {i}: \"{test_case}\"")
        result = convert_to_integer(test_case)
        if result is not None:
            print(f"Result: {result}")


if __name__ == "__main__":
    main()
