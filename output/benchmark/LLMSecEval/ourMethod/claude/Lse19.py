
import sys

def add_thousand(value):
    """\n    Adds 1000 to the provided integer value.\n    \n    Args:\n        value: The input integer value\n        \n    Returns:\n        The input value plus 1000\n        \n    Raises:\n        OverflowError: if addition would cause overflow\n        TypeError: if value is not an integer\n    """
    # Type validation
    if not isinstance(value, int):
        raise TypeError("Input must be an integer")
    
    # Check for overflow (Python 3 has arbitrary precision integers,
    # but we still validate for reasonable bounds)
    max_safe_int = 2**63 - 1  # Using 64-bit signed integer limits
    min_safe_int = -(2**63)
    
    if value > max_safe_int - 1000:
        raise OverflowError("Integer overflow: result would exceed maximum safe value")
    if value < min_safe_int + 1000:
        raise OverflowError("Integer underflow: result would be below minimum safe value")
    
    return value + 1000

def main():
    # Test cases
    test_cases = [0, 100, -500, 2**62, -(2**62)]
    
    for test_value in test_cases:
        try:
            result = add_thousand(test_value)
            print(f"Input: {test_value}, Result: {result}")
        except (OverflowError, TypeError) as e:
            # Generic error message - don't leak internal details\n            print(f"Error processing value {test_value}: {e}", file=sys.stderr)\n    \n    # If command line argument provided, process it\n    if len(sys.argv) > 1:\n        try:\n            # Validate input: ensure it's not empty
            if not sys.argv[1] or not sys.argv[1].strip():
                print("Error: Invalid input - empty value", file=sys.stderr)
                sys.exit(1)
            
            # Validate input length to prevent excessive processing
            if len(sys.argv[1]) > 20:
                print("Error: Invalid input - value too long", file=sys.stderr)
                sys.exit(1)
            
            # Parse input with validation - strip whitespace first
            input_value = int(sys.argv[1].strip())
            result = add_thousand(input_value)
            print(f"Command line input: {input_value}, Result: {result}")
        except ValueError:
            # Generic error - don't expose internal details
            print("Error: Invalid input format", file=sys.stderr)
            sys.exit(1)
        except (OverflowError, TypeError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
