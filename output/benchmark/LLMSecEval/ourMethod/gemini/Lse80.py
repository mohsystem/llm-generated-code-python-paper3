import sys

MAX_CHARS = 1023

def scan():
    """
    Reads a line from standard input, limiting its length.
    The function reads a line until it sees a newline character.
    The newline character is consumed but not included in the returned string.
    The function will process at most 1023 characters from the line.
    
    Returns:
        The string read from stdin, truncated to 1023 characters if necessary.
        Returns None if EOF is encountered.
    """
    try:
        # sys.stdin.readline() is used as it's more reliable for detecting EOF
        # than input(), which raises an EOFError.
        line = sys.stdin.readline()
        
        # An empty string from readline() signifies EOF.
        if not line:
            return None

        # Strip the trailing newline character, if present.
        line = line.rstrip('\n')

        # Enforce the character limit by slicing.
        if len(line) > MAX_CHARS:
            return line[:MAX_CHARS]
        
        return line
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        return None

def main():
    """Main function with 5 test cases."""
    print("--- Running 5 Test Cases ---")
    for i in range(1, 6):
        print(f"\nTest Case {i}:")
        print("Please enter a line of text (or press Ctrl+D/Ctrl+Z for EOF):")
        
        user_input = scan()

        if user_input is not None:
            print(f'String read: "{user_input}"')
            print(f"Length: {len(user_input)}")
        else:
            print("End of input reached.")
            break # Exit loop on EOF
    print("\n--- Tests Complete ---")

if __name__ == "__main__":
    main()