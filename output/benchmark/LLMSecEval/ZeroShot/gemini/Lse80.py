import sys
def scan():
    """
    Reads a line from stdin, emulating a 1024-byte buffer (1023 chars).
    The newline character is not stored. This function is secure against
    buffer overflows as Python strings are dynamically sized. The truncation
    is performed to meet the prompt's requirements.

    Returns:
        A tuple containing (number_of_chars_stored, stored_string).
        On EOF, returns (0, "").
    """
    try:
        # sys.stdin.readline() reads a line including the newline character
        line = sys.stdin.readline()
    except (IOError, EOFError):
        # Handle cases where the stream is closed or an error occurs
        return 0, ""

    # An empty string from readline() indicates End-of-File
    if not line:
        return 0, ""

    # Remove the trailing newline character(s) (\n or \r\n)
    line = line.rstrip('\r\n')

    # The prompt requires emulating a 1024-byte buffer, so we can store
    # at most 1023 characters.
    buffer_limit = 1023
    if len(line) > buffer_limit:
        line = line[:buffer_limit]

    return len(line), line

def main():
    """ Main function with 5 test cases """
    test_prompts = [
        "a short string (e.g., 'hello world'):",
        "an empty string (just press Enter):",
        "a string with exactly 1023 'a' characters:",
        "a string longer than 1023 'b' characters (e.g., 1030 'b's):",
        "a string with special characters and spaces (e.g., '  !@#$%^&*()  '):"
    ]

    print("Running 5 test cases. Please provide input for each.")

    for i in range(5):
        print(f"\n--- Test Case {i + 1} ---")
        print(f"Please enter {test_prompts[i]}")
        
        try:
            chars_read, content = scan()
            print(f"Function returned (chars read): {chars_read}")
            print(f"Content: \"{content}\"")
            print(f"Content length: {len(content)}")
        except Exception as e:
            print(f"An error occurred: {e}", file=sys.stderr)
            break

if __name__ == "__main__":
    main()