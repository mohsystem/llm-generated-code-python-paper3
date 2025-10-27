import sys

def trim_trailing_whitespace(s: str) -> str:
    """
    Trims trailing whitespace characters from a string.

    Args:
        s: The string to trim. It is expected to be a string.
    
    Returns:
        The string with trailing whitespace removed.
    """
    if not isinstance(s, str):
        # Basic type validation
        return ""
    return s.rstrip()

def main():
    """Main function to process command line arguments and run test cases."""
    print("--- Command Line Argument Processing ---")
    if len(sys.argv) > 1:
        # Process the first command line argument
        input_str = sys.argv[1]
        trimmed_str = trim_trailing_whitespace(input_str)
        print(f"Original: \"{input_str}\"")
        print(f"Trimmed:  \"{trimmed_str}\"")
    else:
        # Provide usage instructions if no argument is given
        print(f"Usage: python {sys.argv[0]} \"<string to trim>\"", file=sys.stderr)

    print("\n--- Test Cases ---")
    test_cases = [
        "hello world   ",
        "test\t\n ",
        "already_trimmed",
        "      ",
        ""
    ]
    
    for i, test_str in enumerate(test_cases, 1):
        result = trim_trailing_whitespace(test_str)
        print(f"Test Case {i}:")
        print(f"  Original: \"{test_str}\"")
        print(f"  Trimmed:  \"{result}\"\n")

if __name__ == "__main__":
    main()