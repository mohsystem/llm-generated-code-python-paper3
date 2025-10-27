
import sys

def process_value(input_str):
    """\n    Process input value by adding 1000 and printing result.\n    \n    Args:\n        input_str: String representation of integer input\n        \n    Returns:\n        0 on success, -1 on error\n    """
    # Input validation: check if input is None or empty
    if input_str is None or not input_str.strip():
        print("Error: Input cannot be None or empty", file=sys.stderr)
        return -1
    
    try:
        # Parse input as integer with validation
        # This prevents injection and ensures type safety
        value = int(input_str.strip())
        
        # Check for integer overflow before addition
        # Python 3 has arbitrary precision integers, but we check for practical limits
        MAX_SAFE_INT = sys.maxsize
        MIN_SAFE_INT = -sys.maxsize - 1
        
        if value > MAX_SAFE_INT - 1000:
            print("Error: Value would overflow", file=sys.stderr)
            return -1
        
        if value < MIN_SAFE_INT + 1000:
            print("Error: Value would underflow", file=sys.stderr)
            return -1
        
        # Safe addition after overflow check
        result = value + 1000
        
        # Print result to console using safe output method
        print(result)
        
        return 0
    except ValueError:
        # Handle parsing errors without exposing internal details
        print("Error: Invalid number format", file=sys.stderr)
        return -1
    except Exception:
        # Catch any unexpected errors
        print("Error: Unexpected error occurred", file=sys.stderr)
        return -1


def main():
    """Main function with test cases."""
    # Test cases with input validation
    print("Test 1: Valid positive number")
    process_value("500")
    
    print("\\nTest 2: Valid negative number")
    process_value("-200")
    
    print("\\nTest 3: Zero")
    process_value("0")
    
    print("\\nTest 4: Large number")
    process_value("999999")
    
    print("\\nTest 5: Invalid input")
    process_value("not_a_number")


if __name__ == "__main__":
    main()
