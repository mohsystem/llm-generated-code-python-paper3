import sys

OFFSET = 1000

def add_offset(value):
    """
    Adds a constant offset to the given value.
    In Python, integers have arbitrary precision, so overflow is not a concern
    during the addition itself. The primary security check is on input parsing.
    
    Args:
        value: An integer or float.
    
    Returns:
        The result of the addition.
        
    Raises:
        TypeError: If the input is not a number.
    """
    if not isinstance(value, int):
        raise TypeError("Input must be an integer")
    return value + OFFSET

def run_test(test_input):
    """Helper function to run and display a single test case."""
    print(f'Test Case: "{test_input}" -> ', end="")
    try:
        input_value = int(test_input)
        result = add_offset(input_value)
        print(f"Result: {result}")
    except ValueError:
        print("Error: Invalid number format.")
    except TypeError as e:
        print(f"Error: {e}")

def main():
    """Main function to handle command-line args and run test cases."""
    # Part 1: Handle actual command line input
    if len(sys.argv) == 2:
        print("--- Processing Command Line Input ---")
        try:
            input_value = int(sys.argv[1])
            result = add_offset(input_value)
            print(f"Input: {sys.argv[1]}, Result: {result}")
        except ValueError:
            print("Error: Input must be a valid integer.", file=sys.stderr)
        print("-------------------------------------\n")
    elif len(sys.argv) > 2:
        print(f"Usage: python {sys.argv[0]} <single integer value>", file=sys.stderr)

    # Part 2: Run 5+ built-in test cases as requested
    print("--- Running Built-in Test Cases ---")
    run_test("123")
    run_test("0")
    run_test("-50")
    run_test("9223372036854775807123456789") # Very large number
    run_test("abc") # Invalid format
    run_test("-1000")
    print("-----------------------------------")

if __name__ == "__main__":
    main()