import sys

OFFSET = 1000

def add_offset(value):
    """Adds a constant offset to the given value."""
    return value + OFFSET

def run_tests():
    """Runs 5 hardcoded test cases."""
    print("--- Running 5 Test Cases ---")
    test_cases = [10, 0, -50, 2000, -1000]
    for case in test_cases:
        print(f"Input: {case}, Output: {add_offset(case)}")
    print("--------------------------\n")

def main():
    """Main function to run test cases and handle command line input."""
    run_tests()
    
    # Handling command line input
    if len(sys.argv) > 1:
        try:
            input_value = int(sys.argv[1])
            result = add_offset(input_value)
            print(f"Command line input: {input_value}")
            print(f"Result with offset: {result}")
        except ValueError:
            print("Error: The provided command line argument is not a valid integer.", file=sys.stderr)
    else:
        # sys.argv[0] is the script name itself
        script_name = sys.argv[0]
        print(f"Usage: python {script_name} <integer_value>")

if __name__ == "__main__":
    main()