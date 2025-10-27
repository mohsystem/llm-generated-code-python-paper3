
import sys

def process_input(args):
    # Check if exactly one argument is provided
    if len(args) != 1:
        print("Error: Please provide exactly one argument")
        sys.exit(1)
    
    # Get the argument from command line
    input_str = args[0]
    
    # Print the argument
    print("Original input: " + input_str)
    
    # Trim the trailing whitespace
    input_str = input_str.rstrip()
    
    # Print the argument again
    print("Trimmed input: " + input_str)
    
    # Exit the program
    sys.exit(0)

if __name__ == "__main__":
    # Test case 1: Normal string with trailing spaces
    print("Test Case 1:")
    try:
        process_input(["Hello World   "])
    except SystemExit:
        pass
    
    print("\\nTest Case 2:")
    try:
        process_input(["Test123\\t\\t"])
    except SystemExit:
        pass
    
    print("\\nTest Case 3:")
    try:
        process_input(["NoTrailingSpace"])
    except SystemExit:
        pass
    
    print("\\nTest Case 4:")
    try:
        process_input(["Multiple   Spaces   "])
    except SystemExit:
        pass
    
    print("\\nTest Case 5:")
    try:
        process_input(["   Leading and trailing   "])
    except SystemExit:
        pass
