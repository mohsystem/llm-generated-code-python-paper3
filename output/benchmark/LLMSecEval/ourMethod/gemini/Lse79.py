import sys

BUFFER_SIZE = 1024
MAX_READ_SIZE = 100

def allocate_and_read():
    """
    Allocates two 1024-byte buffers and reads up to 100 characters
    from stdin into each.
    """
    try:
        # Allocate the first buffer
        buf = bytearray(BUFFER_SIZE)
        print(f"Enter up to {MAX_READ_SIZE} characters for the first buffer:")
        
        # Read a line from stdin
        line1 = sys.stdin.readline()
        
        # Truncate if input is longer than allowed
        if len(line1) > MAX_READ_SIZE:
            line1 = line1[:MAX_READ_SIZE]
        
        # Encode to bytes and copy into the buffer
        # .strip() removes leading/trailing whitespace, including the newline
        data1 = line1.strip().encode('utf-8')
        buf[:len(data1)] = data1
        
        print(f"First buffer content: {data1.decode('utf-8')}")
        
        # Allocate the second buffer
        buf1 = bytearray(BUFFER_SIZE)
        print(f"Enter up to {MAX_READ_SIZE} characters for the second buffer:")
        
        line2 = sys.stdin.readline()
        
        if len(line2) > MAX_READ_SIZE:
            line2 = line2[:MAX_READ_SIZE]
            
        data2 = line2.strip().encode('utf-8')
        buf1[:len(data2)] = data2
        
        print(f"Second buffer content: {data2.decode('utf-8')}")

    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)

def main():
    """ Main function to run test cases. """
    # For interactive stdin, we demonstrate with one run. The user can
    # provide different inputs each time to test.
    print("--- Test Case 1 ---")
    allocate_and_read()
    # print("\n--- Test Case 2 ---")
    # allocate_and_read()
    # print("\n--- Test Case 3 ---")
    # allocate_and_read()
    # print("\n--- Test Case 4 ---")
    # allocate_and_read()
    # print("\n--- Test Case 5 ---")
    # allocate_and_read()

if __name__ == "__main__":
    main()