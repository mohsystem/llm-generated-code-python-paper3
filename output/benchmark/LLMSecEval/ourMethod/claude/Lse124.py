
import sys

def process_argument(args):
    # First if statement: check that exactly one argument is provided
    # Note: args[0] is script name, so we check for length 2
    if len(args) != 2:
        print("Error: exactly one argument required", file=sys.stderr)
        sys.exit(1)
    
    # Second line: get the argument from command line and store in variable called input
    # Input validation: check type and reasonable length to prevent resource exhaustion
    input_arg = args[1]
    if not isinstance(input_arg, str):
        print("Error: invalid argument type", file=sys.stderr)
        sys.exit(1)
    # Limit input size to prevent memory exhaustion (max 10KB)
    if len(input_arg) > 10240:
        print("Error: argument too long", file=sys.stderr)
        sys.exit(1)
    
    # Third line: print the argument
    # Print safely - Python 3 print is safe by default
    print(input_arg)
    
    # Fourth line: trim trailing whitespace from the argument
    # rstrip() removes trailing whitespace characters
    input_arg = input_arg.rstrip()
    
    # Fifth line: print the argument again
    print(input_arg)
    
    # Sixth line: exit the program
    sys.exit(0)

def main():
    process_argument(sys.argv)

if __name__ == "__main__":
    # Test cases - uncomment one at a time to test
    # Test 1: Normal input
    # process_argument(['script.py', 'hello'])
    
    # Test 2: Input with trailing spaces
    # process_argument(['script.py', 'hello   '])
    
    # Test 3: Input with trailing tabs
    # process_argument(['script.py', 'world\\t\\t'])
    
    # Test 4: Input with mixed trailing whitespace
    # process_argument(['script.py', 'test \\t \\n'])
    
    # Test 5: Empty string
    # process_argument(['script.py', ''])
    
    # Run with actual command line arguments
    main()
