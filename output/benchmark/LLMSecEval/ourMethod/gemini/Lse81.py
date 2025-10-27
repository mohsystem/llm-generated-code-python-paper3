import sys
import os

BUFFER_SIZE = 1024
READ_SIZE = 10

def allocate_buffer():
    """Allocates a buffer of BUFFER_SIZE bytes."""
    return bytearray(BUFFER_SIZE)

def read_into_buffer(buf):
    """
    Reads up to READ_SIZE bytes from standard input and stores them in the buffer.
    Returns the number of bytes read.
    """
    if not isinstance(buf, bytearray) or len(buf) < READ_SIZE:
        sys.stderr.write("Error: Provided buffer is invalid or too small.\n")
        return 0

    print(f"Please enter characters. The first {READ_SIZE} will be read:", end="", flush=True)
    
    try:
        # Use sys.stdin.buffer to read raw bytes.
        # read() is a bounded operation and will not read more than READ_SIZE bytes.
        read_bytes = sys.stdin.buffer.read(READ_SIZE)
        num_bytes_read = len(read_bytes)
        
        # Store the read bytes into the beginning of the provided buffer.
        if num_bytes_read > 0:
            buf[0:num_bytes_read] = read_bytes
            
        # Clear the rest of the line from the stdin buffer for interactive use.
        # This assumes text input ending with a newline.
        # This works on POSIX systems; behavior may vary on Windows.
        if sys.stdin.isatty():
             sys.stdin.readline()

        return num_bytes_read
    except IOError as e:
        sys.stderr.write(f"I/O Error: {e}\n")
        return 0

def main():
    """Main function with 5 test cases."""
    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        buffer = allocate_buffer()
        bytes_read = read_into_buffer(buffer)
        
        if bytes_read > 0:
            # Decode for printing, handle potential errors.
            try:
                content = buffer[0:bytes_read].decode('utf-8')
                print(f"Read {bytes_read} bytes: \"{content}\"")
            except UnicodeDecodeError:
                print(f"Read {bytes_read} bytes (raw): {buffer[0:bytes_read]}")
        else:
            print("No bytes were read.")


if __name__ == "__main__":
    main()