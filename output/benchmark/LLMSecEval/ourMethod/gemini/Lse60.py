import sys

MAX_BUFFER_SIZE = 65536  # 64 KB limit

def allocate_and_print_buffer(size_str):
    """
    Allocates and prints a buffer of a specified size.
    Validates the size to be a non-negative integer within a defined limit.
    """
    if size_str is None:
        print("Error: Size argument cannot be None.", file=sys.stderr)
        return

    try:
        size = int(size_str)
    except (ValueError, TypeError):
        print(f"Error: Invalid number format for size: '{size_str}'", file=sys.stderr)
        return

    if size < 0:
        print("Error: Buffer size cannot be negative.", file=sys.stderr)
        return

    if size > MAX_BUFFER_SIZE:
        print(f"Error: Buffer size exceeds the maximum allowed limit of {MAX_BUFFER_SIZE} bytes.", file=sys.stderr)
        return

    try:
        # A bytearray is a mutable sequence of integers in the range 0 <= x < 256.
        # It is initialized with null bytes (zeros).
        buffer = bytearray(size)
        print(f"Allocated a buffer of size: {size}")
        print("Buffer contents (hex):")
        if not buffer:
            print("(empty)")
        else:
            for i in range(0, len(buffer), 16):
                chunk = buffer[i:i+16]
                hex_part = ' '.join(f'{byte:02x}' for byte in chunk)
                # The character part is omitted as buffer contents are not guaranteed to be printable
                print(f'{i:08x}: {hex_part}')

    except MemoryError:
        print("Error: Failed to allocate buffer due to insufficient memory.", file=sys.stderr)
    finally:
        print("--------------------")


def main():
    """
    Main function to handle command-line arguments and run test cases.
    """
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <buffer_size>")
        print("\nRunning test cases:")
        
        print("Test Case 1: Valid size (16)")
        allocate_and_print_buffer("16")

        print("Test Case 2: Zero size")
        allocate_and_print_buffer("0")

        print("Test Case 3: Negative size (-5, invalid)")
        allocate_and_print_buffer("-5")

        print("Test Case 4: Non-numeric size ('abc', invalid)")
        allocate_and_print_buffer("abc")

        print(f"Test Case 5: Size too large ({MAX_BUFFER_SIZE + 1}, invalid)")
        allocate_and_print_buffer(str(MAX_BUFFER_SIZE + 1))
        return

    allocate_and_print_buffer(sys.argv[1])

if __name__ == "__main__":
    main()