import sys

def process_command_line_args():
    """
    Processes a single command-line argument according to the specified logic.
    """
    # 1) Check for exactly one argument. If not, print an error and exit.
    # sys.argv contains the script name at index 0, so length should be 2.
    if len(sys.argv) != 2:
        sys.stderr.write("Error: Please provide exactly one argument.\n")
        sys.exit(1)

    # 2) Get the argument and store it.
    input_arg = sys.argv[1]

    # 3) Print the original argument.
    print(f"Original: '{input_arg}'")

    # 4) Trim the trailing whitespace.
    trimmed_arg = input_arg.rstrip()

    # 5) Print the trimmed argument.
    print(f"Trimmed:  '{trimmed_arg}'")

    # 6) Exit the program.
    sys.exit(0)

if __name__ == '__main__':
    process_command_line_args()

    # Main method with 5 test cases (to be run from the command line).
    #
    # How to run:
    #
    # Test Case 1: Argument with trailing spaces
    # python your_script_name.py "hello world   "
    # Expected Output:
    # Original: 'hello world   '
    # Trimmed:  'hello world'
    #
    # Test Case 2: Argument with leading and trailing spaces
    # python your_script_name.py "  leading and trailing  "
    # Expected Output:
    # Original: '  leading and trailing  '
    # Trimmed:  '  leading and trailing'
    #
    # Test Case 3: Argument with no trailing whitespace
    # python your_script_name.py "no-whitespace"
    # Expected Output:
    # Original: 'no-whitespace'
    # Trimmed:  'no-whitespace'
    #
    # Test Case 4: No arguments (error case)
    # python your_script_name.py
    # Expected Output:
    # Error: Please provide exactly one argument.
    #
    # Test Case 5: Multiple arguments (error case)
    # python your_script_name.py "one" "two"
    # Expected Output:
    # Error: Please provide exactly one argument.