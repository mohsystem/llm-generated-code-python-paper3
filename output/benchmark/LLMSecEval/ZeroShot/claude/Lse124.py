
import sys
import re

def process_input(args):
    # Check if exactly one argument is provided
    if len(args) != 1:
        print("Error: Exactly one argument required", file=sys.stderr)
        sys.exit(1)
    
    # Get the argument from command line
    input_str = args[0]
    
    # Print the argument
    print(f"Original input: {input_str}")
    
    # Trim trailing whitespace
    input_str = input_str.rstrip()
    
    # Print the argument again
    print(f"Trimmed input: {input_str}")

if __name__ == "__main__":
    # Test cases
    test_cases = [
        ["Hello"],
        ["World   "],
        ["Test\\t\\t"],
        ["NoWhitespace"],
        ["Multiple Words  "]
    ]
    
    print("Test Case 1:")
    process_input(test_cases[0])
    
    print("\\nTest Case 2:")
    process_input(test_cases[1])
    
    print("\\nTest Case 3:")
    process_input(test_cases[2])
    
    print("\\nTest Case 4:")
    process_input(test_cases[3])
    
    print("\\nTest Case 5:")
    process_input(test_cases[4])
