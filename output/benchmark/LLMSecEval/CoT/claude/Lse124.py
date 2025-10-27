
import sys
import re

def main():
    # Check if exactly one argument is provided
    if len(sys.argv) != 2:
        print("Error: Exactly one argument is required.", file=sys.stderr)
        sys.exit(1)
    
    # Get the argument from command line
    input_arg = sys.argv[1]
    
    # Print the argument
    print(f"Original: {input_arg}")
    
    # Trim trailing whitespace
    input_arg = input_arg.rstrip()
    
    # Print the trimmed argument
    print(f"Trimmed: {input_arg}")
    
    # Exit the program
    sys.exit(0)

if __name__ == "__main__":
    main()
