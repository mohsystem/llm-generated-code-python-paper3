import sys

def process_argument(argv):
    """
    Processes a single command-line argument based on the prompt's logic.
    argv is a list simulating sys.argv (script name + arguments).
    """
    # 1. Check if exactly one argument is provided. (len should be 2: script + arg)
    if len(argv) != 2:
        print("Error: Please provide exactly one argument.", file=sys.stderr)
        # 6. Exit the logical flow.
        return

    # 2. Get the argument.
    input_arg = argv[1]

    # 3. Print the original argument.
    print(f"Original: '{input_arg}'")

    # 4. Trim the trailing whitespace from the argument.
    trimmed_input = input_arg.rstrip()

    # 5. Print the argument again.
    print(f"Trimmed: '{trimmed_input}'")
    
    # 6. The function ends, effectively exiting this logical block.

if __name__ == "__main__":
    # In a real script, you would call process_argument(sys.argv)
    # Here, we simulate it with 5 test cases.
    
    print("--- Test Case 1: No arguments ---")
    process_argument(["script.py"]) # Simulates no user arguments

    print("\n--- Test Case 2: Two arguments ---")
    process_argument(["script.py", "first", "second"])

    print("\n--- Test Case 3: One argument, no trailing space ---")
    process_argument(["script.py", "hello"])

    print("\n--- Test Case 4: One argument with trailing spaces ---")
    process_argument(["script.py", "world  "])

    print("\n--- Test Case 5: One argument with leading and trailing spaces ---")
    process_argument(["script.py", "  spaced out   "])