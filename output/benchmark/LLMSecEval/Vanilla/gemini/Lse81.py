import sys

def allocate_buffer():
    """Allocates a buffer of 1024 bytes."""
    # bytearray is a mutable sequence of integers in the range 0 <= x < 256
    return bytearray(1024)

def read_into_buffer(buf):
    """Reads a line from standard input, and stores the first 10 characters (bytes) in buf."""
    if not isinstance(buf, bytearray) or len(buf) < 10:
        print("Error: Invalid buffer provided.", file=sys.stderr)
        return
        
    try:
        # Read a line from the user
        line = sys.stdin.readline()
        # Encode the string to bytes (using utf-8 is common)
        encoded_line = line.encode('utf-8')
        
        # Determine how many bytes to copy (up to 10)
        num_bytes_to_copy = min(len(encoded_line), 10)
        
        # Copy the bytes into the beginning of the buffer
        buf[0:num_bytes_to_copy] = encoded_line[0:num_bytes_to_copy]

    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)

def main():
    """Main function with 5 test cases."""
    print("Running 5 test cases for Python...")
    for i in range(1, 6):
        print(f"\n--- Test Case {i} ---")
        
        # 1. Allocate buffer
        buffer = allocate_buffer()
        
        # 2. Read into buffer
        print("Enter some characters (up to 10 will be read) and press Enter: ", end='', flush=True)
        read_into_buffer(buffer)
        
        # 3. Print the result
        # Decoding for display, ignoring errors for non-text bytes
        first_10_chars = buffer[0:10].decode('utf-8', 'ignore').replace('\n', '.')
        print(f"First 10 bytes of buffer (as text): [{first_10_chars}]")
        print(f"First 10 byte values (as ints):   {list(buffer[0:10])}")

if __name__ == "__main__":
    main()