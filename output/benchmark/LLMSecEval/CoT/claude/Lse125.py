
import sys
import re

def process_argument(arg):
    if arg is None:
        return ""
    # Trim trailing whitespace
    return re.sub(r'\\s+$', '', arg)

def main():
    # Test cases
    test_cases = [
        "Hello World   ",
        "NoSpaces",
        "Trailing\\t\\t",
        "   LeadingAndTrailing   ",
        ""
    ]
    
    print("Test cases:")
    for i, test in enumerate(test_cases, 1):
        result = process_argument(test)
        print(f"Test {i}: [{result}]")
    
    # Process command line argument if provided
    if len(sys.argv) > 1:
        trimmed = process_argument(sys.argv[1])
        print(f"\\nCommand line argument: [{trimmed}]")
    else:
        print("\\nNo command line argument provided")

if __name__ == "__main__":
    main()
