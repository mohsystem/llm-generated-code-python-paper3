import sys
import os

def add_thousand(input_str):
    """
    Parses a string to an integer, adds 1000, and returns the result.
    This function is secure against invalid number formats. Python's arbitrary-
    precision integers prevent overflow issues.

    Args:
        input_str: The string representation of the number.

    Returns:
        The result as an integer, or None if the input is invalid.
    """
    if not isinstance(input_str, str):
        return None
        
    try:
        # Secure: Use a try-except block to handle non-integer input gracefully.
        num = int(input_str.strip())
        return num + 1000
    except (ValueError, TypeError):
        return None

def main():
    """ Main function to handle command-line args and run test cases. """
    # Part 1: Process command-line argument if provided.
    if len(sys.argv) == 2:
        print(f"Processing command-line argument: {sys.argv[1]}")
        result = add_thousand(sys.argv[1])
        if result is not None:
            print(f"Result: {result}")
        else:
            print(f"Error: Invalid number format '{sys.argv[1]}'", file=sys.stderr)
        print("\n-----------------------------------------\n")
    elif len(sys.argv) > 2:
        script_name = os.path.basename(sys.argv[0])
        print(f"Usage: python {script_name} <number>", file=sys.stderr)
        print("Ignoring extra arguments and running test cases.", file=sys.stderr)
        print("\n-----------------------------------------\n")

    # Part 2: Run 5 hardcoded test cases to demonstrate functionality.
    print("Running 5 test cases...")
    test_cases = [
        "50",                           # 1. Valid positive number
        "-50",                          # 2. Valid negative number
        "0",                            # 3. Zero
        "not a number",                 # 4. Invalid non-numeric input
        "92233720368547758070000"       # 5. A very large number (Python handles this)
    ]

    for i, test_input in enumerate(test_cases, 1):
        print(f"Test Case {i}: Input = \"{test_input}\"")
        result = add_thousand(test_input)
        if result is not None:
            print(f"  -> Result: {result}")
        else:
            print(f"  -> Error: Invalid number format")

if __name__ == "__main__":
    main()