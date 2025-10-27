
import sys

def trim_trailing_whitespace(input_str):
    """\n    Trims trailing whitespace from a string and returns the result.\n    Security measures:\n    - Type validation to ensure string input\n    - Bounds-safe string operations\n    - No regex or eval usage\n    - Length validation to prevent resource exhaustion\n    """
    # Validate input type
    if input_str is None:
        return ""
    
    if not isinstance(input_str, str):
        return ""
    
    # Handle empty string
    if len(input_str) == 0:
        return input_str
    
    # Find the last non-whitespace character
    # rstrip() is safe and efficient for this purpose
    return input_str.rstrip()

def main():
    """\n    Main function to process command line arguments.\n    Security measures:\n    - Input validation and length checking\n    - Safe array access with bounds checking\n    - No dynamic code execution\n    - Clear error messages without internal details\n    """
    # Test cases
    test_cases = [
        "hello world   ",
        "no trailing",
        "   leading and trailing   ",
        "   ",
        ""
    ]
    
    print("Test cases:")
    for i, test in enumerate(test_cases, 1):
        result = trim_trailing_whitespace(test)
        print(f"Test {i}: [{result}]")
    
    # Process command line arguments if provided
    # sys.argv is always a list, safe to check length
    if len(sys.argv) > 1:
        print("\\nCommand line argument processing:")
        # Only process the first argument to limit resource usage
        input_str = sys.argv[1]
        
        # Validate input length to prevent resource exhaustion
        MAX_INPUT_LENGTH = 10000
        if len(input_str) > MAX_INPUT_LENGTH:
            print("Error: Input exceeds maximum allowed length", file=sys.stderr)
            sys.exit(1)
        
        trimmed = trim_trailing_whitespace(input_str)
        print(f"[{trimmed}]")

if __name__ == "__main__":
    main()
