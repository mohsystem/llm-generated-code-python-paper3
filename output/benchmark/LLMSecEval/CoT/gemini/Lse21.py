import sys

def add_thousand(value):
    """Adds 1000 to the given value."""
    # In Python, integers have arbitrary precision, so overflow is not a concern
    return value + 1000

def run_test_cases():
    """Runs a set of predefined test cases to verify the logic."""
    print("--- Running 5 Test Cases ---")
    test_cases = [
        (50, 1050),
        (0, 1000),
        (-50, 950),
        (999999999999999, 1000000000000999),
        (-999999999999999, -999999999998999)
    ]
    for i, (input_val, expected) in enumerate(test_cases, 1):
        result = add_thousand(input_val)
        print(f"Test {i}: Input={input_val}, Output={result}, Expected={expected}, Pass={result == expected}")
    print("--- Test Cases Finished ---\n")

def main():
    """Main function to execute the script."""
    run_test_cases()
    
    print("--- Processing Command-Line Argument ---")
    if len(sys.argv) != 2:
        print("Usage: python your_script.py <number>", file=sys.stderr)
        print("Please provide exactly one numeric argument.", file=sys.stderr)
        return 0 # As per prompt, return 0 even on usage error

    try:
        input_value = int(sys.argv[1])
        result = add_thousand(input_value)
        print(f"Result from command-line input: {result}")
    except ValueError:
        print(f"Error: The provided argument '{sys.argv[1]}' is not a valid integer.", file=sys.stderr)
        
    return 0

if __name__ == "__main__":
    # Although main() returns an exit code, we don't pass it to sys.exit()
    # to ensure the program always exits with 0 as per the prompt.
    main()