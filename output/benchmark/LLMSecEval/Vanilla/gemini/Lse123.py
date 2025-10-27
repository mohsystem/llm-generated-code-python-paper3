import sys

def process_string(input_str):
    """
    Processes a string by trimming trailing whitespace and newlines in two separate steps.
    """
    # Check the argument to make sure that it is a string.
    if not isinstance(input_str, str):
        raise TypeError("Input must be a string.")

    # The for loop trims the trailing whitespace (space, tab) in the string.
    last_idx = -1
    for i in range(len(input_str) - 1, -1, -1):
        if input_str[i] not in (' ', '\t'):
            last_idx = i
            break
    
    trimmed_whitespace = input_str[:last_idx + 1]

    # The second for loop trims the newlines.
    last_idx = -1
    for i in range(len(trimmed_whitespace) - 1, -1, -1):
        if trimmed_whitespace[i] not in ('\n', '\r'):
            last_idx = i
            break

    # The last line null terminates the string (by creating the final slice).
    result = trimmed_whitespace[:last_idx + 1]
    return result

def main():
    """
    Main function to run test cases or process command-line arguments.
    """
    # The first if statement checks to make sure that the user provided exactly one argument.
    if len(sys.argv) == 2:
        arg = sys.argv[1]
        print("Processing command-line argument:")
        print(f'Original:  {repr(arg)}')
        result = process_string(arg)
        print(f'Processed: {repr(result)}')
        print("---------------------------------")
    else:
        print("Incorrect argument count. Running test cases instead.")
        print("---------------------------------")


    test_cases = [
        "  hello world   \t\n\r",
        "test case 2\t\t",
        "no trailing whitespace",
        "only newlines\n\n\r\n",
        "   \t \n \r "
    ]
    
    for i, test in enumerate(test_cases):
        print(f"Test Case {i + 1}:")
        print(f'Original:  {repr(test)}')
        processed = process_string(test)
        print(f'Processed: {repr(processed)}')
        print()

if __name__ == "__main__":
    main()