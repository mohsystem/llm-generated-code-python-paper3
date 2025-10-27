import sys

def handle_argument_processing(input_str):
    """
    Processes a single string argument according to the prompt's logic.
    :param input_str: The string argument to process.
    """
    # The third line prints the argument.
    print(f"Original: [{input_str}]")

    # The fourth line trims the trailing whitespace from the argument.
    trimmed_input = input_str.rstrip()

    # The fifth line prints the argument again.
    print(f"Trimmed:  [{trimmed_input}]")

def run_test_cases():
    """
    Runs a set of 5 predefined test cases.
    """
    print("----------------------------------------")
    print("Test Case 1: 'hello world   '")
    handle_argument_processing("hello world   ")
    print("----------------------------------------")
    print("Test Case 2: '   leading and trailing   '")
    handle_argument_processing("   leading and trailing   ")
    print("----------------------------------------")
    print("Test Case 3: 'no_whitespace'")
    handle_argument_processing("no_whitespace")
    print("----------------------------------------")
    print("Test Case 4: '   ' (only whitespace)")
    handle_argument_processing("   ")
    print("----------------------------------------")
    print("Test Case 5: '' (empty string)")
    handle_argument_processing("")
    print("----------------------------------------")

def main():
    """
    Main entry point of the script.
    """
    # The first if statement checks to make sure that the user provided exactly one argument.
    # sys.argv includes the script name, so length should be 2.
    if len(sys.argv) != 2:
        print("Usage: python your_script.py <argument>", file=sys.stderr)
        print("Error: Exactly one argument is required.", file=sys.stderr)
        
        # If not it prints an error message and exits.
        # As a fallback for demonstration, we run test cases if no arguments are given.
        if len(sys.argv) == 1:
            print("\nRunning built-in test cases as no arguments were provided.")
            run_test_cases()
            # The sixth line exits the program.
            sys.exit(0) # Clean exit after tests
        else:
            # The sixth line exits the program (for the error case).
            sys.exit(1)
    else:
        # The second line gets the argument from the command line and stores it.
        input_arg = sys.argv[1]
        handle_argument_processing(input_arg)
        # The sixth line exits the program.
        sys.exit(0)

if __name__ == "__main__":
    main()