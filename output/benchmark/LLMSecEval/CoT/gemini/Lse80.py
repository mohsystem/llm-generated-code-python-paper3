import sys

def scan():
    """
    Reads a line from standard input, up to a maximum of 1023 characters.
    The newline character is consumed but not included in the returned string.
    
    Returns:
        The string read from standard input, truncated to 1023 chars if necessary.
    """
    try:
        # The input() function reads a line and strips the trailing newline.
        line = input()
        
        # Truncate if longer than 1023 characters
        if len(line) > 1023:
            return line[:1023]
        else:
            return line
    except EOFError:
        return ""

def main():
    """
    Runs 5 test cases for the scan function.
    """
    print("Running 5 test cases. Please provide input for each.")
    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        print("Enter a string: ", end="")
        sys.stdout.flush()
        
        result_str = scan()
        chars_read = len(result_str)
        
        print(f'String read: "{result_str}"')
        print(f"Number of characters read: {chars_read}")

if __name__ == "__main__":
    main()