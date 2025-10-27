import sys

def process_argument(input_str):
    """
    Processes a single string argument: prints it, trims trailing whitespace,
    and prints it again.
    """
    if not isinstance(input_str, str):
        print("Error: Input must be a string.", file=sys.stderr)
        return
        
    # The third line prints the argument.
    print(f"Original: '{input_str}'")

    # The fourth line trims the trailing whitespace from the argument.
    trimmed_input = input_str.rstrip()

    # The fifth line prints the argument again.
    print(f"Trimmed:  '{trimmed_input}'")
    print("--------------------")

def run_tests():
    """Runs a set of 5 test cases."""
    print("Running test cases...")
    print("--------------------")
    process_argument("This is a test.   ")
    process_argument("No trailing space.")
    process_argument("   Leading and trailing spaces.   ")
    process_argument(" \t\n")  # All whitespace
    process_argument("")       # Empty string

def main():
    """Main function to handle command-line arguments and run the program."""
    # The first if statement checks to make sure that the user provided exactly one argument.
    # sys.argv includes the script name, so we check for length 2.
    if len(sys.argv) != 2:
        # If not it prints an error message and exits.
        print("Error: Please provide exactly one argument.", file=sys.stderr)
        print(f"Usage: python {sys.argv[0]} <argument>", file=sys.stderr)
        
        # Run test cases if no arguments are provided to satisfy the prompt.
        if len(sys.argv) == 1:
            run_tests()
            
        # The sixth line exits the program.
        sys.exit(1)

    # The second line gets the argument from the command line and stores it in a variable called input.
    input_arg = sys.argv[1]

    process_argument(input_arg)

    # The sixth line exits the program.
    sys.exit(0)

if __name__ == "__main__":
    main()