import sys

# A reasonable upper limit for buffer size to prevent Denial of Service attacks
MAX_BUFFER_SIZE = 1024 * 1024  # 1MB

def process_buffer(size):
    """
    Allocates a buffer of a given size and prints its contents.
    """
    print(f"--- Processing request for buffer of size: {size} ---")
    
    if not isinstance(size, int):
        print("Error: Size must be an integer.", file=sys.stderr)
        print("--- Finished processing ---", flush=True)
        print()
        return
        
    if size < 0:
        print("Error: Buffer size cannot be negative.", file=sys.stderr)
        print("--- Finished processing ---", flush=True)
        print()
        return
        
    if size > MAX_BUFFER_SIZE:
        print(f"Error: Requested buffer size {size} exceeds maximum allowed size of {MAX_BUFFER_SIZE}.", file=sys.stderr)
        print("--- Finished processing ---", flush=True)
        print()
        return

    try:
        # In Python, a new bytearray is initialized with null bytes.
        buffer = bytearray(size)
        print(f"Buffer of size {size} allocated successfully.")
        
        # The prompt asks to print the contents. In Python, this will be all null bytes.
        if size > 0:
            print("Buffer contents: ", end="")
            print_limit = min(size, 32)
            # Elements of bytearray are integers from 0 to 255.
            for i in range(print_limit):
                print(f"{buffer[i]:02X} ", end="")
            if size > print_limit:
                print("...", end="")
            print()
        else:
            print("Buffer is empty.")

    except MemoryError:
        print(f"Error: Failed to allocate buffer of size {size}. Out of memory.", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
    
    print("--- Finished processing ---", flush=True)
    print()

def main():
    """
    Main function to handle command-line arguments or run test cases.
    """
    if len(sys.argv) == 2:
        try:
            size = int(sys.argv[1])
            process_buffer(size)
        except ValueError:
            print(f"Error: Invalid number format '{sys.argv[1]}'. Please provide an integer.", file=sys.stderr)
    elif len(sys.argv) == 1:
        print("No command-line argument provided. Running test cases.")
        # 5 test cases
        process_buffer(16)          # Test Case 1: A small, valid size
        process_buffer(0)           # Test Case 2: A zero size
        process_buffer(1)           # Test Case 3: A size of 1
        process_buffer(-10)         # Test Case 4: An invalid negative size
        process_buffer(2000000)     # Test Case 5: A size that exceeds our custom limit
    else:
        print("Usage: python your_script_name.py <buffer_size>", file=sys.stderr)

if __name__ == "__main__":
    main()