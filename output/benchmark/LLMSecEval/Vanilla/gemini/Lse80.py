import sys

def scan(buffer):
    """
    Reads a line from stdin, stores at most 1023 characters into the
    provided buffer (a list), and returns the number of characters read.
    The newline character is consumed but not stored.

    :param buffer: A list to be cleared and filled with characters from the input line.
    :return: The number of characters read and stored in the buffer.
    """
    line = sys.stdin.readline()
    
    # rstrip handles both '\n' and potential EOF without a newline
    line = line.rstrip('\n\r')

    # Truncate to a maximum of 1023 characters
    truncated_line = line[:1023]

    # Clear the buffer and populate it with the new characters
    buffer.clear()
    buffer.extend(list(truncated_line))

    return len(buffer)

def main():
    """ Main function with 5 test cases """
    print("Running 5 test cases for Python scan function.")
    
    # The buffer is a list, which is a mutable type in Python
    # similar to passing a character array in C/C++.
    string_buffer = []

    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        print("Please enter a string: ", end="")
        sys.stdout.flush()

        chars_read = scan(string_buffer)
        
        content = "".join(string_buffer)
        print(f"Function returned (characters read): {chars_read}")
        print(f"Buffer content: \"{content}\"")
        print(f"Buffer length: {len(string_buffer)}")

if __name__ == "__main__":
    main()