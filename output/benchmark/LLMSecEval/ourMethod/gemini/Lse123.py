import sys

def trim_trailing_whitespace(s: str) -> str:
    """
    Trims trailing whitespace characters (space, tab, newline, etc.) from a string.
    The prompt describes separate loops for whitespace and newlines, but a single
    loop is more efficient as isspace() handles both.
    """
    # Check the argument to make sure that it is a string.
    if not isinstance(s, str):
        # This check is good practice for functions but redundant for sys.argv.
        raise TypeError("Input must be a string")

    if not s:
        return ""

    # The loop trims the trailing whitespace and newlines in the string.
    end_index = len(s) - 1
    while end_index >= 0 and s[end_index].isspace():
        end_index -= 1
    
    return s[:end_index + 1]

def main():
    """
    Main function to handle command-line arguments and run test cases.
    """
    # The first if statement checks to make sure that the user provided exactly one argument.
    if len(sys.argv) != 2:
        print("Usage: python your_script_name.py \"<string to trim>\"", file=sys.stderr)
        print("\n--- Running Test Cases ---", file=sys.stdout)

        # Test cases
        test_cases = [
            ("hello world  ", "hello world"),
            ("test\t\n \r", "test"),
            ("already_clean", "already_clean"),
            ("   \t\n", ""),
            ("", "")
        ]

        for i, (original, expected) in enumerate(test_cases):
            print(f"--- Test Case {i+1} ---")
            print(f"Original: \"{original}\"")
            result = trim_trailing_whitespace(original)
            print(f"Trimmed : \"{result}\"")
            assert result == expected
            print("")
        
        print("All test cases passed.")
        sys.exit(1)

    input_str = sys.argv[1]
    print(f"Original: \"{input_str}\"")
    trimmed_str = trim_trailing_whitespace(input_str)
    print(f"Trimmed : \"{trimmed_str}\"")

if __name__ == "__main__":
    main()