
import sys

OFFSET = 1000
# Prevent integer overflow by setting safe bounds
MAX_INPUT_VALUE = sys.maxsize - OFFSET
MIN_INPUT_VALUE = -sys.maxsize - 1 - OFFSET

def add_offset(input_str):
    """\n    Adds an offset of 1000 to the input value.\n    \n    Args:\n        input_str: String representation of an integer\n        \n    Returns:\n        Integer result of input + OFFSET\n        \n    Raises:\n        ValueError: If input is invalid or would cause overflow\n    """
    # Input validation: check for None or empty string
    if input_str is None or not input_str.strip():
        raise ValueError("Input cannot be None or empty")
    
    # Sanitize input: remove leading/trailing whitespace
    sanitized = input_str.strip()
    
    try:
        # Parse input as integer with validation
        value = int(sanitized)
        
        # Integer overflow/underflow check before addition
        if value > MAX_INPUT_VALUE:
            raise ArithmeticError("Input value too large, would cause overflow")
        if value < MIN_INPUT_VALUE:
            raise ArithmeticError("Input value too small, would cause underflow")
        
        # Safe addition after validation
        return value + OFFSET
    except ValueError:
        # Avoid leaking internal details in error message
        raise ValueError("Invalid numeric input")

def main():
    # Test case 1: Normal positive value
    try:
        input1 = "500"
        result1 = add_offset(input1)
        print(f"Input: {input1}, Result: {result1}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    
    # Test case 2: Negative value
    try:
        input2 = "-200"
        result2 = add_offset(input2)
        print(f"Input: {input2}, Result: {result2}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    
    # Test case 3: Zero
    try:
        input3 = "0"
        result3 = add_offset(input3)
        print(f"Input: {input3}, Result: {result3}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    
    # Test case 4: Large value near max (should prevent overflow)
    try:
        input4 = "9223372036854774807"
        result4 = add_offset(input4)
        print(f"Input: {input4}, Result: {result4}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    
    # Test case 5: Invalid input
    try:
        input5 = "invalid"
        result5 = add_offset(input5)
        print(f"Input: {input5}, Result: {result5}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
