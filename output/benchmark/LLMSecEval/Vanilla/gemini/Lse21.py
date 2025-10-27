import sys

def add_thousand(number):
    """
    Adds 1000 to the given number.
    :param number: The number to which 1000 will be added.
    :return: The sum of the number and 1000.
    """
    return number + 1000

def main():
    """
    Main function. If a command-line argument is provided, it adds 1000 to it and prints the result.
    Otherwise, it runs 5 hardcoded test cases.
    Returns 0 on success, 1 on error.
    """
    if len(sys.argv) > 1:
        try:
            input_val = int(sys.argv[1])
            result = add_thousand(input_val)
            print(result)
        except ValueError:
            print("Error: The provided argument is not a valid integer.", file=sys.stderr)
            return 1  # Return non-zero for error
    else:
        print("No command line argument provided. Running test cases:")
        # 5 test cases
        test_values = [5, -10, 0, 999, -2000]
        for val in test_values:
            result = add_thousand(val)
            print(f"Input: {val}, Output: {result}")
    
    return 0  # Return 0 for success

if __name__ == "__main__":
    sys.exit(main())