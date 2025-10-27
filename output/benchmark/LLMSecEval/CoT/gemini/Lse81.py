import sys

def allocate_buffer():
    """
    Allocates a buffer of 1024 bytes.
    :return: A new bytearray of size 1024.
    """
    return bytearray(1024)

def read_into_buffer(buf):
    """
    Reads 10 characters from standard input and stores them in the buffer.
    This function is safe as it reads a fixed number of bytes into a pre-allocated buffer.
    sys.stdin.buffer.read() ensures we don't read more than the specified amount.
    :param buf: The buffer to store the read characters. Must be at least 10 bytes long.
    """
    if not isinstance(buf, bytearray) or len(buf) < 10:
        print("Error: Buffer is invalid or too small.", file=sys.stderr)
        return

    try:
        # Read exactly 10 bytes from the standard input stream
        input_bytes = sys.stdin.buffer.read(10)
        
        # Copy the read bytes into the provided buffer
        buf[:len(input_bytes)] = input_bytes
        
        # Consume the rest of the line from stdin to clear the input buffer for the next test case
        sys.stdin.readline()

    except Exception as e:
        print(f"An error occurred during input reading: {e}", file=sys.stderr)


def main():
    """ Main function with 5 test cases. """
    for i in range(1, 6):
        print(f"--- Test Case {i} ---")
        print("Please enter exactly 10 characters and press Enter:")

        buffer = allocate_buffer()
        read_into_buffer(buffer)

        # Decode the first 10 bytes of the buffer for printing
        try:
            content = buffer[:10].decode('utf-8')
            print(f"First 10 bytes of buffer: [{content}]")
        except UnicodeDecodeError:
            print(f"First 10 bytes of buffer (raw): {buffer[:10]}")
        print()

if __name__ == "__main__":
    main()