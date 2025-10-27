import sys

def add_thousand(number):
    """
    Adds 1000 to the given number.
    :param number: The input number (integer).
    :return: The input number plus 1000.
    """
    return number + 1000

def main():
    """
    Main function to handle command-line arguments or run test cases.
    """
    # If a command-line argument is provided, process it.
    if len(sys.argv) > 1:
        try:
            input_number = int(sys.argv[1])
            result = add_thousand(input_number)
            print(result)
        except ValueError:
            print("Error: Input must be a valid integer.", file=sys.stderr)
    else:
        # Otherwise, run the 5 built-in test cases.
        print("No command-line argument provided. Running test cases:")
        test_cases = [10, -50, 0, 12345, -1000]
        for test_input in test_cases:
            result = add_thousand(test_input)
            print(f"Input: {test_input}, Output: {result}")

if __name__ == "__main__":
    main()